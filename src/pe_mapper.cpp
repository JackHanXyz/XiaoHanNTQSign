// pe_mapper.cpp —— PE 手动映射实现。
#include "pe_mapper.h"

#include <windows.h>

#include <cstring>
#include <fstream>
#include <mutex>

#include "log.h"

namespace xh {

namespace {

std::mutex g_dir_mu;
std::vector<std::string> g_search_dirs;

bool read_file(const std::wstring &path, std::vector<uint8_t> &out)
{
    std::ifstream f(path.c_str(), std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamoff sz = f.tellg();
    if (sz <= 0) return false;
    f.seekg(0);
    out.resize(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char *>(out.data()), sz);
    return f.good();
}

// 允许常见小写节名之外的情况：包装成 RtlImageNtHeader 也行，这里直接按偏移取。
const IMAGE_NT_HEADERS64 *nt_headers(const std::vector<uint8_t> &file)
{
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file.size())
        return nullptr;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

HMODULE load_dependency(const std::string &name)
{
    // 优先交给系统按已注册的用户目录搜索（能连带解决依赖 DLL 的依赖）。
    if (HMODULE h = LoadLibraryW(std::wstring(name.begin(), name.end()).c_str()))
        return h;

    // 退一步：逐个拼接完整路径直接加载。
    {
        std::lock_guard<std::mutex> lk(g_dir_mu);
        for (const auto &dir : g_search_dirs) {
            std::string full = dir + "\\" + name;
            std::wstring w(full.begin(), full.end());
            if (HMODULE h = LoadLibraryW(w.c_str())) return h;
        }
    }
    return nullptr;
}

}  // namespace

PeImage::~PeImage()
{
    if (base_) VirtualFree(base_, 0, MEM_RELEASE);
}

void PeImage::add_search_dir(const std::string &dir)
{
    // 把目录注册进进程 DLL 搜索路径：wrapper.node 导入的 libvips / QQNT.dll 等
    // 都在 QQ 版本目录下，只靠默认搜索找不到，其自身依赖也需要同目录解析。
    static std::once_flag once;
    std::call_once(once, [] {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
                                 LOAD_LIBRARY_SEARCH_USER_DIRS);
    });

    std::wstring wdir(dir.begin(), dir.end());
    if (GetFileAttributesW(wdir.c_str()) != INVALID_FILE_ATTRIBUTES) {
        AddDllDirectory(wdir.c_str());
    }

    std::lock_guard<std::mutex> lk(g_dir_mu);
    for (const auto &d : g_search_dirs) {
        if (d == dir) return;
    }
    g_search_dirs.push_back(dir);
}

PeImage *PeImage::load(const std::wstring &path, bool resolve_imports_flag,
                       std::string *err)
{
    std::vector<uint8_t> file;
    if (!read_file(path, file)) {
        if (err) *err = "无法读取文件";
        return nullptr;
    }

    const IMAGE_NT_HEADERS64 *nt = nt_headers(file);
    if (!nt) {
        if (err) *err = "不是有效的 PE 文件（缺少 MZ/PE 签名）";
        return nullptr;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        if (err) *err = "非 x64 映像，本工具只处理 AMD64";
        return nullptr;
    }
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        if (err) *err = "不是 DLL 映像（.node 应为 DLL）";
        return nullptr;
    }

    PeImage *img = new PeImage();
    img->preferred_base_ = nt->OptionalHeader.ImageBase;
    img->image_size_ = nt->OptionalHeader.SizeOfImage;

    if (!img->map_sections(file, err) ||
        !img->apply_relocations(file, err)) {
        delete img;
        return nullptr;
    }
    if (resolve_imports_flag && !img->resolve_imports(file)) {
        LOGW("部分导入未能解析（见 unresolved_imports），签名调用可能失败");
    }
    return img;
}

bool PeImage::map_sections(const std::vector<uint8_t> &file, std::string *err)
{
    // 优先按映像首选基址分配，失败则让系统选（随后靠重定位修正）。
    uint8_t *mem = static_cast<uint8_t *>(
        VirtualAlloc(reinterpret_cast<void *>(preferred_base_), image_size_,
                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!mem) {
        mem = static_cast<uint8_t *>(VirtualAlloc(nullptr, image_size_,
                                                  MEM_RESERVE | MEM_COMMIT,
                                                  PAGE_EXECUTE_READWRITE));
    }
    if (!mem) {
        if (err) *err = "VirtualAlloc 失败";
        return false;
    }
    base_ = mem;
    actual_base_ = reinterpret_cast<uint64_t>(mem);
    std::memset(base_, 0, image_size_);

    const IMAGE_NT_HEADERS64 *nt = nt_headers(file);
    size_t hdr = nt->OptionalHeader.SizeOfHeaders;
    if (hdr > file.size()) hdr = file.size();
    std::memcpy(base_, file.data(), hdr);

    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        size_t raw = sec[i].SizeOfRawData;
        size_t va = sec[i].VirtualAddress;
        size_t raw_off = sec[i].PointerToRawData;
        if (raw == 0 || va >= image_size_) continue;
        if (raw_off + raw > file.size()) {
            raw = (raw_off < file.size()) ? (file.size() - raw_off) : 0;
        }
        if (va + raw > image_size_) raw = image_size_ - va;
        if (raw) std::memcpy(base_ + va, file.data() + raw_off, raw);
    }
    return true;
}

bool PeImage::apply_relocations(const std::vector<uint8_t> &file, std::string *err)
{
    if (actual_base_ == preferred_base_) return true;  // 无需修正

    const IMAGE_NT_HEADERS64 *nt = nt_headers(file);
    const IMAGE_DATA_DIRECTORY &dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) {
        // 没有重定位表又没能在首选基址落位 —— 映像无法安全使用。
        if (err) *err = "映像无重定位表，且未落在首选基址";
        return false;
    }

    int64_t delta = static_cast<int64_t>(actual_base_) -
                    static_cast<int64_t>(preferred_base_);
    size_t off = 0;
    while (off + sizeof(IMAGE_BASE_RELOCATION) <= dir.Size) {
        auto blk = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
            base_ + dir.VirtualAddress + off);
        if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

        size_t count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto items = reinterpret_cast<const WORD *>(blk + 1);
        for (size_t i = 0; i < count; i++) {
            WORD type = items[i] >> 12;
            WORD ofs = items[i] & 0x0FFF;
            uint8_t *p = base_ + blk->VirtualAddress + ofs;
            if (type == IMAGE_REL_BASED_DIR64) {
                *reinterpret_cast<uint64_t *>(p) += static_cast<uint64_t>(delta);
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // 填充项，跳过
            }
        }
        off += blk->SizeOfBlock;
    }
    return true;
}

bool PeImage::resolve_imports(const std::vector<uint8_t> &file)
{
    const IMAGE_NT_HEADERS64 *nt = nt_headers(file);
    const IMAGE_DATA_DIRECTORY &dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0) return true;

    bool all_ok = true;
    auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(
        base_ + dir.VirtualAddress);
    for (; desc->Name; desc++) {
        const char *dll = reinterpret_cast<const char *>(base_ + desc->Name);
        HMODULE dep = load_dependency(dll);
        if (!dep) {
            unresolved_.push_back(std::string(dll) + " (模块加载失败)");
            all_ok = false;
            continue;
        }

        auto thunk = reinterpret_cast<const IMAGE_THUNK_DATA64 *>(
            base_ + (desc->FirstThunk ? desc->FirstThunk : desc->OriginalFirstThunk));
        auto orig = desc->OriginalFirstThunk
            ? reinterpret_cast<const IMAGE_THUNK_DATA64 *>(base_ + desc->OriginalFirstThunk)
            : nullptr;
        auto iat = reinterpret_cast<IMAGE_THUNK_DATA64 *>(base_ + desc->FirstThunk);

        for (; thunk->u1.AddressOfData; thunk++, iat++) {
            FARPROC fn = nullptr;
            std::string sym;
            if (orig && (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                unsigned ord = static_cast<unsigned>(thunk->u1.Ordinal & 0xFFFF);
                fn = GetProcAddress(dep, reinterpret_cast<const char *>(ord));
                sym = std::string(dll) + "!#" + std::to_string(ord);
            } else {
                auto ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(
                    base_ + thunk->u1.AddressOfData);
                fn = GetProcAddress(dep, reinterpret_cast<const char *>(ibn->Name));
                sym = std::string(dll) + "!" + reinterpret_cast<const char *>(ibn->Name);
            }
            if (fn) {
                iat->u1.Function = reinterpret_cast<uint64_t>(fn);
                iat_symbols_[reinterpret_cast<uintptr_t>(iat)] = sym;
            } else {
                unresolved_.push_back(sym);
                all_ok = false;
            }
        }
    }
    return all_ok;
}

uintptr_t PeImage::rva_to_va(uint64_t rva) const
{
    if (!valid_rva(rva)) return 0;
    return reinterpret_cast<uintptr_t>(base_ + rva);
}

bool PeImage::valid_rva(uint64_t rva) const
{
    return base_ && rva < image_size_;
}

std::vector<uint8_t> PeImage::read_bytes(uint64_t rva, size_t n) const
{
    std::vector<uint8_t> out;
    if (!valid_rva(rva) || rva + n > image_size_) return out;
    out.assign(base_ + rva, base_ + rva + n);
    return out;
}

std::string PeImage::symbol_for_iat(uintptr_t va) const
{
    auto it = iat_symbols_.find(va);
    return it == iat_symbols_.end() ? std::string() : it->second;
}

}  // namespace xh