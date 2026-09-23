#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// ------------------------------------------------------------
// RAII HANDLE
// ------------------------------------------------------------

class Handle {
public:
    Handle() = default;

    explicit Handle(HANDLE h) : h_(h) {}

    ~Handle() {
        if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr) {
            CloseHandle(h_);
        }
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle(Handle&& other) noexcept : h_(other.h_) {
        other.h_ = INVALID_HANDLE_VALUE;
    }

    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr)
                CloseHandle(h_);

            h_ = other.h_;
            other.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const {
        return h_;
    }

    bool valid() const {
        return h_ != INVALID_HANDLE_VALUE && h_ != nullptr;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// Find* search handles must be closed with FindClose(), not CloseHandle().
class FindHandle {
public:
    FindHandle() = default;

    explicit FindHandle(HANDLE h) : h_(h) {}

    ~FindHandle() {
        if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr)
            FindClose(h_);
    }

    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;

    FindHandle(FindHandle&& other) noexcept : h_(other.h_) {
        other.h_ = INVALID_HANDLE_VALUE;
    }

    FindHandle& operator=(FindHandle&& other) noexcept {
        if (this != &other) {
            if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr)
                FindClose(h_);

            h_ = other.h_;
            other.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const {
        return h_;
    }

    bool valid() const {
        return h_ != INVALID_HANDLE_VALUE && h_ != nullptr;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// ------------------------------------------------------------
// Fehlerbehandlung
// ------------------------------------------------------------

std::string WideToUtf8(const std::wstring& s)
{
    if (s.empty())
        return {};

    int n = WideCharToMultiByte(
        CP_UTF8,
        0,
        s.c_str(),
        static_cast<int>(s.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (n <= 0)
        return "<conversion failed>";

    std::string out(static_cast<size_t>(n), '\0');

    WideCharToMultiByte(
        CP_UTF8,
        0,
        s.c_str(),
        static_cast<int>(s.size()),
        &out[0],
        n,
        nullptr,
        nullptr
    );

    return out;
}

std::wstring WinErrorText(DWORD err)
{
    LPWSTR p = nullptr;

    DWORD n = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        err,
        0,
        reinterpret_cast<LPWSTR>(&p),
        0,
        nullptr
    );

    std::wstring result;

    if (n && p)
        result.assign(p, n);
    else
        result = L"Windows error " + std::to_wstring(err);

    if (p)
        LocalFree(p);

    return result;
}

[[noreturn]]
void ThrowWin32(const wchar_t* what, DWORD err = GetLastError())
{
    std::wstring msg =
        std::wstring(what) +
        L": " +
        WinErrorText(err);

    throw std::runtime_error(WideToUtf8(msg));
}

[[noreturn]]
void Fail(const std::string& msg)
{
    throw std::runtime_error(msg);
}

// File data lives only in the MFT (no non-resident LCN extents).
struct ResidentDataError : std::runtime_error {
    explicit ResidentDataError(const std::string& msg)
        : std::runtime_error(msg) {}
};

// ------------------------------------------------------------
// SHA-256 via Windows CNG / BCrypt
// ------------------------------------------------------------

class Sha256 {
public:
    Sha256()
    {
        NTSTATUS s = BCryptOpenAlgorithmProvider(
            &alg_,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0
        );

        Check(s, "BCryptOpenAlgorithmProvider");

        DWORD cb = 0;
        DWORD got = 0;

        s = BCryptGetProperty(
            alg_,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&cb),
            sizeof(cb),
            &got,
            0
        );

        Check(s, "BCryptGetProperty(BCRYPT_OBJECT_LENGTH)");

        object_.resize(cb);

        DWORD hashLen = 0;

        s = BCryptGetProperty(
            alg_,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLen),
            sizeof(hashLen),
            &got,
            0
        );

        Check(s, "BCryptGetProperty(BCRYPT_HASH_LENGTH)");

        hashLength_ = hashLen;

        s = BCryptCreateHash(
            alg_,
            &hash_,
            object_.data(),
            static_cast<ULONG>(object_.size()),
            nullptr,
            0,
            0
        );

        Check(s, "BCryptCreateHash");
    }

    ~Sha256()
    {
        if (hash_)
            BCryptDestroyHash(hash_);

        if (alg_)
            BCryptCloseAlgorithmProvider(alg_, 0);
    }

    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    void Update(const void* data, size_t length)
    {
        const BYTE* p = static_cast<const BYTE*>(data);

        while (length) {
            ULONG n = static_cast<ULONG>(
                std::min<size_t>(length, 1024 * 1024)
            );

            NTSTATUS s = BCryptHashData(
                hash_,
                const_cast<PUCHAR>(p),
                n,
                0
            );

            Check(s, "BCryptHashData");

            p += n;
            length -= n;
        }
    }

    std::vector<BYTE> Finish()
    {
        std::vector<BYTE> result(hashLength_);

        NTSTATUS s = BCryptFinishHash(
            hash_,
            result.data(),
            static_cast<ULONG>(result.size()),
            0
        );

        Check(s, "BCryptFinishHash");

        return result;
    }

private:
    static void Check(NTSTATUS status, const char* where)
    {
        if (status < 0) {
            std::ostringstream oss;
            oss << where
                << " failed, NTSTATUS=0x"
                << std::hex
                << static_cast<unsigned long>(status);

            throw std::runtime_error(oss.str());
        }
    }

    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<BYTE> object_;
    DWORD hashLength_ = 0;
};

std::string Hex(const std::vector<BYTE>& hash)
{
    std::ostringstream oss;

    oss << std::hex << std::setfill('0');

    for (BYTE b : hash)
        oss << std::setw(2) << static_cast<unsigned>(b);

    return oss.str();
}

// ------------------------------------------------------------
// Extents
// ------------------------------------------------------------

struct Extent {
    LONGLONG vcnStart = 0;
    LONGLONG vcnEnd = 0;       // exklusiv
    LONGLONG lcnStart = 0;

    LONGLONG ClusterCount() const {
        return vcnEnd - vcnStart;
    }
};

bool SameExtents(
    const std::vector<Extent>& a,
    const std::vector<Extent>& b)
{
    if (a.size() != b.size())
        return false;

    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].vcnStart != b[i].vcnStart ||
            a[i].vcnEnd   != b[i].vcnEnd   ||
            a[i].lcnStart != b[i].lcnStart)
            return false;
    }

    return true;
}

std::vector<Extent> GetExtents(HANDLE file)
{
    STARTING_VCN_INPUT_BUFFER input{};
    input.StartingVcn.QuadPart = 0;

    size_t bufferSize = 1024 * 1024;

    for (;;) {
        if (bufferSize > 64ull * 1024ull * 1024ull)
            Fail("Retrieval-pointer buffer became unexpectedly large.");

        std::vector<BYTE> buffer(bufferSize);
        DWORD returned = 0;

        BOOL ok = DeviceIoControl(
            file,
            FSCTL_GET_RETRIEVAL_POINTERS,
            &input,
            sizeof(input),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &returned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();

            if (err == ERROR_MORE_DATA) {
                bufferSize *= 2;
                continue;
            }

            if (err == ERROR_HANDLE_EOF)
                throw ResidentDataError(
                    "No non-resident extents: file data is resident "
                    "in the NTFS MFT and has no wipeable LCN clusters."
                );

            ThrowWin32(
                L"FSCTL_GET_RETRIEVAL_POINTERS",
                err
            );
        }

        auto* rp =
            reinterpret_cast<RETRIEVAL_POINTERS_BUFFER*>(
                buffer.data()
            );

        if (rp->ExtentCount == 0)
            throw ResidentDataError(
                "The file has no non-resident data extents: "
                "data is resident in the NTFS MFT "
                "and has no wipeable LCN clusters."
            );

        if (rp->StartingVcn.QuadPart != 0)
            Fail("Unexpected StartingVcn != 0.");

        size_t minimum =
            FIELD_OFFSET(RETRIEVAL_POINTERS_BUFFER, Extents) +
            static_cast<size_t>(rp->ExtentCount) *
            sizeof(rp->Extents[0]);

        if (returned < minimum)
            Fail("Invalid RETRIEVAL_POINTERS_BUFFER returned by Windows.");

        std::vector<Extent> result;
        result.reserve(rp->ExtentCount);

        LONGLONG currentVcn = rp->StartingVcn.QuadPart;

        for (DWORD i = 0; i < rp->ExtentCount; ++i) {
            LONGLONG nextVcn =
                rp->Extents[i].NextVcn.QuadPart;

            LONGLONG lcn =
                rp->Extents[i].Lcn.QuadPart;

            if (nextVcn <= currentVcn)
                Fail("Invalid VCN extent.");

            // -1 is used for sparse/unallocated areas and some
            // compressed-file representations.
            if (lcn < 0)
                Fail(
                    "Extent has LCN < 0. "
                    "Sparse/compressed allocation is not supported."
                );

            result.push_back({
                currentVcn,
                nextVcn,
                lcn
            });

            currentVcn = nextVcn;
        }

        return result;
    }
}

// ------------------------------------------------------------
// Datei-Hash
// ------------------------------------------------------------

std::vector<BYTE> HashFile(
    HANDLE file,
    uint64_t length)
{
    LARGE_INTEGER zero{};
    zero.QuadPart = 0;

    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        ThrowWin32(L"SetFilePointerEx(file)");

    Sha256 hash;

    std::vector<BYTE> buffer(1024 * 1024);

    uint64_t remaining = length;

    while (remaining) {
        DWORD wanted = static_cast<DWORD>(
            std::min<uint64_t>(
                remaining,
                buffer.size()
            )
        );

        DWORD got = 0;

        if (!ReadFile(
                file,
                buffer.data(),
                wanted,
                &got,
                nullptr))
        {
            ThrowWin32(L"ReadFile(file)");
        }

        if (got == 0)
            Fail("Unexpected EOF while hashing file.");

        hash.Update(buffer.data(), got);
        remaining -= got;
    }

    return hash.Finish();
}

std::vector<BYTE> HashZeros(uint64_t length)
{
    Sha256 hash;

    std::vector<BYTE> zero(1024 * 1024, 0);

    while (length) {
        size_t n = static_cast<size_t>(
            std::min<uint64_t>(
                length,
                zero.size()
            )
        );

        hash.Update(zero.data(), n);
        length -= n;
    }

    return hash.Finish();
}

// ------------------------------------------------------------
// Volume
// ------------------------------------------------------------

struct VolumeInfo {
    std::wstring mountPoint;
    std::wstring guidPath;     // mit abschließendem "\"
    std::wstring devicePath;   // ohne abschließendes "\"

    DWORD sectorsPerCluster = 0;
    DWORD bytesPerSector = 0;

    uint64_t clusterSize = 0;
};

VolumeInfo GetVolumeInfo(const std::wstring& filePath)
{
    wchar_t mount[MAX_PATH]{};

    if (!GetVolumePathNameW(
            filePath.c_str(),
            mount,
            static_cast<DWORD>(std::size(mount))))
    {
        ThrowWin32(L"GetVolumePathNameW");
    }

    wchar_t fsName[MAX_PATH]{};

    if (!GetVolumeInformationW(
            mount,
            nullptr,
            0,
            nullptr,
            nullptr,
            nullptr,
            fsName,
            static_cast<DWORD>(std::size(fsName))))
    {
        ThrowWin32(L"GetVolumeInformationW");
    }

    if (_wcsicmp(fsName, L"NTFS") != 0)
        Fail("This program intentionally supports NTFS only.");

    wchar_t volumeName[MAX_PATH]{};

    if (!GetVolumeNameForVolumeMountPointW(
            mount,
            volumeName,
            static_cast<DWORD>(std::size(volumeName))))
    {
        ThrowWin32(L"GetVolumeNameForVolumeMountPointW");
    }

    DWORD sectorsPerCluster = 0;
    DWORD bytesPerSector = 0;
    DWORD freeClusters = 0;
    DWORD totalClusters = 0;

    if (!GetDiskFreeSpaceW(
            mount,
            &sectorsPerCluster,
            &bytesPerSector,
            &freeClusters,
            &totalClusters))
    {
        ThrowWin32(L"GetDiskFreeSpaceW");
    }

    if (!sectorsPerCluster || !bytesPerSector)
        Fail("Invalid cluster/sector geometry.");

    VolumeInfo info;

    info.mountPoint = mount;
    info.guidPath = volumeName;
    info.devicePath = volumeName;

    // CreateFile expects the volume GUID path WITHOUT the final '\'.
    if (!info.devicePath.empty() &&
        info.devicePath.back() == L'\\')
    {
        info.devicePath.pop_back();
    }

    info.sectorsPerCluster = sectorsPerCluster;
    info.bytesPerSector = bytesPerSector;

    info.clusterSize =
        static_cast<uint64_t>(sectorsPerCluster) *
        static_cast<uint64_t>(bytesPerSector);

    return info;
}

Handle OpenVolumeReadOnly(const VolumeInfo& vi)
{
    HANDLE h = CreateFileW(
        vi.devicePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE)
        ThrowWin32(
            L"CreateFile(volume). "
            L"Try running from an elevated Administrator terminal"
        );

    return Handle(h);
}

// ------------------------------------------------------------
// Raw-LCN-Hash
// ------------------------------------------------------------

uint64_t RoundUp(uint64_t value, uint64_t alignment)
{
    if (!alignment)
        Fail("RoundUp alignment == 0.");

    uint64_t rem = value % alignment;

    if (!rem)
        return value;

    return value + (alignment - rem);
}

// Raw read of the file's currently allocated clusters via LCN.
// A zero-hash here only proves that the currently mapped clusters
// read back as zero. It does not prove that older copies no longer
// exist in SSD flash cells, storage firmware, snapshots, backups,
// or other layers above the block device.
std::vector<BYTE> HashRawExtents(
    HANDLE volume,
    const std::vector<Extent>& extents,
    uint64_t clusterSize,
    DWORD bytesPerSector,
    uint64_t logicalLength)
{
    if (!bytesPerSector)
        Fail("bytesPerSector == 0.");

    const size_t alignment =
        std::max<size_t>(
            bytesPerSector,
            sizeof(void*)
        );

    // Multiple of the sector size.
    size_t bufferSize =
        (1024 * 1024 / bytesPerSector) *
        bytesPerSector;

    if (bufferSize < bytesPerSector)
        bufferSize = bytesPerSector;

    void* rawBuffer =
        _aligned_malloc(bufferSize, alignment);

    if (!rawBuffer)
        throw std::bad_alloc();

    struct BufferGuard {
        void* p;
        ~BufferGuard() {
            if (p)
                _aligned_free(p);
        }
    } guard{ rawBuffer };

    Sha256 hash;

    uint64_t hashed = 0;

    for (const Extent& e : extents) {
        uint64_t logicalStart =
            static_cast<uint64_t>(e.vcnStart) *
            clusterSize;

        uint64_t logicalEnd =
            static_cast<uint64_t>(e.vcnEnd) *
            clusterSize;

        if (logicalStart >= logicalLength)
            break;

        logicalEnd =
            std::min(logicalEnd, logicalLength);

        if (logicalEnd <= logicalStart)
            continue;

        uint64_t extentLength =
            logicalEnd - logicalStart;

        uint64_t rawOffset =
            static_cast<uint64_t>(e.lcnStart) *
            clusterSize;

        uint64_t remaining = extentLength;

        while (remaining) {
            size_t toHash =
                static_cast<size_t>(
                    std::min<uint64_t>(
                        remaining,
                        bufferSize
                    )
                );

            // Volume handles are effectively noncached on Microsoft
            // file systems, so keep offset, buffer and request sector-aligned.
            DWORD toRead =
                static_cast<DWORD>(
                    RoundUp(
                        toHash,
                        bytesPerSector
                    )
                );

            LARGE_INTEGER pos{};
            pos.QuadPart =
                static_cast<LONGLONG>(rawOffset);

            if (!SetFilePointerEx(
                    volume,
                    pos,
                    nullptr,
                    FILE_BEGIN))
            {
                ThrowWin32(
                    L"SetFilePointerEx(volume)"
                );
            }

            DWORD got = 0;

            if (!ReadFile(
                    volume,
                    rawBuffer,
                    toRead,
                    &got,
                    nullptr))
            {
                ThrowWin32(
                    L"ReadFile(volume)"
                );
            }

            if (got != toRead)
                Fail(
                    "Short raw read from volume."
                );

            hash.Update(rawBuffer, toHash);

            rawOffset += toHash;
            remaining -= toHash;
            hashed += toHash;
        }
    }

    if (hashed != logicalLength) {
        std::ostringstream oss;
        oss << "Extents covered "
            << hashed
            << " bytes, but "
            << logicalLength
            << " bytes were expected.";

        Fail(oss.str());
    }

    return hash.Finish();
}

// ------------------------------------------------------------
// Schreiben mit Nullen
// ------------------------------------------------------------

void SetFileLength(
    HANDLE file,
    uint64_t newLength)
{
    LARGE_INTEGER pos{};
    pos.QuadPart =
        static_cast<LONGLONG>(newLength);

    if (!SetFilePointerEx(
            file,
            pos,
            nullptr,
            FILE_BEGIN))
    {
        ThrowWin32(L"SetFilePointerEx(SetFileLength)");
    }

    if (!SetEndOfFile(file))
        ThrowWin32(L"SetEndOfFile");
}

void ZeroRange(
    HANDLE file,
    uint64_t offset,
    uint64_t length)
{
    LARGE_INTEGER pos{};
    pos.QuadPart =
        static_cast<LONGLONG>(offset);

    if (!SetFilePointerEx(
            file,
            pos,
            nullptr,
            FILE_BEGIN))
    {
        ThrowWin32(L"SetFilePointerEx(ZeroRange)");
    }

    std::vector<BYTE> zeros(
        1024 * 1024,
        0
    );

    while (length) {
        DWORD n = static_cast<DWORD>(
            std::min<uint64_t>(
                length,
                zeros.size()
            )
        );

        DWORD written = 0;

        if (!WriteFile(
                file,
                zeros.data(),
                n,
                &written,
                nullptr))
        {
            ThrowWin32(L"WriteFile");
        }

        if (written != n)
            Fail("Short WriteFile while zeroing.");

        length -= written;
    }
}

// Best-effort restore of the original logical EOF after --wipe-slack
// temporarily extended it. Activated only after SetEndOfFile succeeded;
// commit() is called after an explicit successful restore so the
// destructor does not restore twice.
class EofRestoreGuard {
public:
    EofRestoreGuard(HANDLE file, uint64_t originalSize)
        : file_(file), originalSize_(originalSize), active_(true) {}

    ~EofRestoreGuard() {
        if (active_) {
            LARGE_INTEGER pos{};
            pos.QuadPart = static_cast<LONGLONG>(originalSize_);

            if (SetFilePointerEx(file_, pos, nullptr, FILE_BEGIN))
                SetEndOfFile(file_);
        }
    }

    EofRestoreGuard(const EofRestoreGuard&) = delete;
    EofRestoreGuard& operator=(const EofRestoreGuard&) = delete;

    void commit() {
        active_ = false;
    }

private:
    HANDLE file_;
    uint64_t originalSize_;
    bool active_;
};

// ------------------------------------------------------------
// Darstellung
// ------------------------------------------------------------

void PrintExtents(
    const std::vector<Extent>& extents,
    uint64_t clusterSize)
{
    std::wcout
        << L"\nVCN -> LCN extents\n"
        << L"------------------------------------------------------------\n";

    for (size_t i = 0; i < extents.size(); ++i) {
        const Extent& e = extents[i];

        uint64_t rawByteOffset =
            static_cast<uint64_t>(e.lcnStart) *
            clusterSize;

        std::wcout
            << L"#" << i
            << L": VCN ["
            << e.vcnStart
            << L", "
            << e.vcnEnd
            << L")  -> LCN "
            << e.lcnStart
            << L"   clusters="
            << e.ClusterCount()
            << L"   rawOffset="
            << rawByteOffset
            << L"\n";
    }

    std::wcout
        << L"------------------------------------------------------------\n";
}

// ------------------------------------------------------------
// Optionen / Ergebnisse
// ------------------------------------------------------------

enum class Mode {
    Verify,
    Wipe,
    WipeSlack
};

struct Options {
    Mode mode = Mode::Wipe;
    bool verbose = false;
    bool recursive = false;
    bool noVerify = false;
    bool dryRun = false;
    bool yes = false;
};

enum class FileStatus {
    Verified,
    Wiped,
    Empty,
    Skipped,
    Unsupported,
    Failed,
    WouldWipe,
    WouldVerify
};

struct FileResult {
    std::wstring path;
    FileStatus status = FileStatus::Failed;
    std::string message;
};

struct VolumeContext {
    std::wstring guid;
    VolumeInfo info;
    Handle volume;
    bool valid = false;
};

FileResult MakeResult(
    const std::wstring& path,
    FileStatus status,
    std::string message = {})
{
    FileResult r;
    r.path = path;
    r.status = status;
    r.message = std::move(message);
    return r;
}

FileResult SkipOrFail(
    const std::wstring& path,
    std::string message,
    const Options& opts)
{
    if (!opts.recursive)
        Fail(message);

    return MakeResult(path, FileStatus::Skipped, std::move(message));
}

bool EnsureVolume(
    const std::wstring& path,
    const Options& opts,
    VolumeContext& vc,
    std::string& error)
{
    if (vc.valid)
        return true;

    try {
        vc.info = GetVolumeInfo(path);
        vc.guid = vc.info.guidPath;

        // Raw LCN verification needs an open volume handle (admin).
        // Dry-run only checks NTFS/mount geometry and never needs the
        // raw volume handle, so it stays unprivileged.
        if (!opts.noVerify && !opts.dryRun)
            vc.volume = OpenVolumeReadOnly(vc.info);

        vc.valid = true;
        return true;
    }
    catch (const std::exception& e) {
        error = e.what();
        vc = VolumeContext{};
        return false;
    }
}

// ------------------------------------------------------------
// Gemeinsame Eligibility-Checks (read-only, kein Schreiben)
// ------------------------------------------------------------

// Returns empty string when the file is eligible for the current mode;
// otherwise a reason suitable for SKIP/FAIL reporting.
std::string ValidateCandidate(
    DWORD attrs,
    DWORD nNumberOfLinks,
    const Options& opts)
{
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        return "Directories are not supported.";

    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
        return "Reparse points/symlinks are intentionally rejected.";

    if (attrs & FILE_ATTRIBUTE_SPARSE_FILE)
        return "Sparse files are not supported.";

    if (attrs & FILE_ATTRIBUTE_COMPRESSED)
        return "NTFS-compressed files are not supported.";

    if (attrs & FILE_ATTRIBUTE_ENCRYPTED)
        return "EFS-encrypted files are not supported.";

    if (attrs & FILE_ATTRIBUTE_OFFLINE)
        return "Offline files are not supported.";

    const bool wipe =
        opts.mode == Mode::Wipe ||
        opts.mode == Mode::WipeSlack;

    if (wipe && nNumberOfLinks > 1) {
        return
            "File has multiple hard links. "
            "Wiping it would affect all names referring to this file.";
    }

    return {};
}

// Compression, encryption and sparseness are per-stream states
// (MS: File Streams). Validate them on every opened stream handle,
// not only on the default-stream handle.
std::string ValidateStreamCandidate(DWORD attrs)
{
    if (attrs & FILE_ATTRIBUTE_SPARSE_FILE)
        return
            "ADS stream is sparse; per-stream attribute not supported "
            "(file not wiped or deleted).";

    if (attrs & FILE_ATTRIBUTE_COMPRESSED)
        return
            "NTFS-compressed ADS stream not supported "
            "(file not wiped or deleted).";

    if (attrs & FILE_ATTRIBUTE_ENCRYPTED)
        return
            "EFS-encrypted ADS stream not supported "
            "(file not wiped or deleted).";

    if (attrs & FILE_ATTRIBUTE_OFFLINE)
        return
            "Offline ADS stream not supported "
            "(file not wiped or deleted).";

    return {};
}

// ------------------------------------------------------------
// NTFS alternate data streams
// ------------------------------------------------------------

struct StreamInfoEntry {
    // Full name as returned by FileStreamInfo, e.g. "::$DATA"
    // or ":zone.identifier:$DATA".
    std::wstring cStreamName;
    uint64_t size = 0;
    uint64_t allocSize = 0;

    bool IsDefault() const {
        return cStreamName == L"::$DATA" || cStreamName == L":";
    }

    // Named $DATA stream (":name:$DATA"). Non-$DATA streams such as
    // $INDEX_ALLOCATION are filtered out explicitly.
    bool IsNamedData() const {
        if (IsDefault())
            return false;

        static const std::wstring suffix = L":$DATA";

        if (cStreamName.size() <= suffix.size())
            return false;

        return cStreamName.compare(
            cStreamName.size() - suffix.size(),
            suffix.size(),
            suffix
        ) == 0;
    }
};

std::vector<StreamInfoEntry> QueryStreams(HANDLE file)
{
    std::vector<BYTE> buffer(64 * 1024);

    for (;;) {
        BOOL ok = GetFileInformationByHandleEx(
            file,
            FileStreamInfo,
            buffer.data(),
            static_cast<DWORD>(buffer.size())
        );

        if (ok)
            break;

        DWORD err = GetLastError();

        if (err == ERROR_MORE_DATA) {
            buffer.resize(buffer.size() * 2);
            continue;
        }

        // Documented: FileStreamInfo with no streams → ERROR_HANDLE_EOF.
        if (err == ERROR_HANDLE_EOF)
            return {};

        ThrowWin32(L"GetFileInformationByHandleEx(FileStreamInfo)", err);
    }

    std::vector<StreamInfoEntry> result;
    DWORD offset = 0;

    for (;;) {
        if (offset + FIELD_OFFSET(FILE_STREAM_INFO, StreamName) >
            buffer.size())
        {
            Fail("FILE_STREAM_INFO entry overruns stream buffer.");
        }

        auto* e = reinterpret_cast<FILE_STREAM_INFO*>(
            buffer.data() + offset
        );

        size_t nameBytes = e->StreamNameLength;

        if (offset + FIELD_OFFSET(FILE_STREAM_INFO, StreamName) +
            nameBytes >
            buffer.size())
        {
            Fail("FILE_STREAM_INFO stream name overruns buffer.");
        }

        StreamInfoEntry entry;
        entry.cStreamName.assign(
            e->StreamName,
            nameBytes / sizeof(wchar_t)
        );
        entry.size = static_cast<uint64_t>(e->StreamSize.QuadPart);
        entry.allocSize =
            static_cast<uint64_t>(e->StreamAllocationSize.QuadPart);
        result.push_back(std::move(entry));

        if (e->NextEntryOffset == 0)
            break;

        offset += e->NextEntryOffset;
    }

    return result;
}

std::wstring StreamOpenPath(
    const std::wstring& filePath,
    const StreamInfoEntry& s)
{
    // cStreamName already includes the leading colon.
    return filePath + s.cStreamName;
}

// ------------------------------------------------------------
// Gemeinsame Preflight-/Wipe-Phasen für alle $DATA-Streams
// ------------------------------------------------------------

// All-stream --wipe-slack / extent preconditions. Must pass for
// every stream before the first ZeroRange on any stream (Phase A).
void PreflightStreamCompat(
    uint64_t sf,
    uint64_t sa,
    const std::vector<Extent>& streamExtents,
    const char* streamLabel,
    bool wipeSlack,
    uint64_t clusterSize)
{
    if (wipeSlack && sa > sf) {
        uint64_t normalAllocation =
            RoundUp(sf, clusterSize);

        if (sa != normalAllocation) {
            Fail(
                std::string("--wipe-slack refused: ")
                    + streamLabel +
                    " AllocationSize contains preallocated "
                    "clusters beyond the normal final cluster."
            );
        }
    }

    if (sf > 0 && !streamExtents.empty()) {
        uint64_t coveredBytes =
            static_cast<uint64_t>(
                streamExtents.back().vcnEnd
            ) * clusterSize;

        if (coveredBytes < sf)
            Fail(
                std::string("VCN extents do not cover ")
                    + streamLabel + " logical size."
            );

        if (coveredBytes < sa)
            Fail(
                std::string("VCN extents do not cover ")
                    + streamLabel + " AllocationSize."
            );
    }
}

// Phase A, read-only: normal stream SHA-256 must equal the direct
// LCN SHA-256 before any stream of this file is written.
void PreWriteVerifyStream(
    HANDLE sh,
    uint64_t sf,
    const std::vector<Extent>& streamExtents,
    bool isDefaultStream,
    const Options& opts,
    const VolumeInfo& vi,
    VolumeContext& vc,
    bool quiet)
{
    if (opts.noVerify || sf == 0)
        return;

    if (!quiet) {
        std::cout
            << (isDefaultStream
                    ? "\nPre-write verification...\n"
                    : "\nADS pre-write verification...\n");
    }

    std::vector<BYTE> normalBefore =
        HashFile(sh, sf);

    std::vector<BYTE> rawBefore =
        HashRawExtents(
            vc.volume.get(),
            streamExtents,
            vi.clusterSize,
            vi.bytesPerSector,
            sf
        );

    if (!quiet) {
        std::cout
            << "normal SHA-256: "
            << Hex(normalBefore)
            << "\n"
            << "raw    SHA-256: "
            << Hex(rawBefore)
            << "\n";
    }

    if (normalBefore != rawBefore) {
        Fail(
            "ABORT: normal stream data and direct LCN reads "
            "do not match."
        );
    }

    if (!quiet)
        std::cout
            << "Pre-write comparison: OK\n";
}

// Phase B, destructive: overwrite one $DATA stream (extent check
// immediately before the write, optional --wipe-slack, post-verify).
// All non-destructive preconditions and pre-write hashes for every
// stream of the file must already have passed (Phase A).
void WipeStreamPhaseB(
    HANDLE sh,
    uint64_t sf,
    uint64_t sa,
    std::vector<Extent>& streamExtents,
    bool isDefaultStream,
    const Options& opts,
    const VolumeInfo& vi,
    VolumeContext& vc,
    bool quiet)
{
    if (!isDefaultStream && sf == 0)
        return;

    const bool wipeSlack =
        opts.mode == Mode::WipeSlack;

    std::vector<Extent> beforeWrite =
        GetExtents(sh);

    if (!SameExtents(streamExtents, beforeWrite))
        Fail("ABORT: extent mapping changed before write.");

    if (!quiet)
        std::cout
            << "\nZEROING "
            << sf
            << " logical bytes...\n";

    ZeroRange(sh, 0, sf);

    if (!FlushFileBuffers(sh))
        ThrowWin32(L"FlushFileBuffers(stream)");

    if (wipeSlack && sa > sf) {
        // Slack compatibility for this stream was checked in
        // PreflightStreamCompat before any ZeroRange.
        uint64_t normalAllocation =
            RoundUp(sf, vi.clusterSize);

        if (sa != normalAllocation) {
            Fail(
                "--wipe-slack refused: AllocationSize contains "
                "preallocated clusters beyond the normal final cluster."
            );
        }

        if (!quiet)
            std::cout
                << "Zeroing final-cluster slack: "
                << (sa - sf)
                << " bytes\n";

        SetFileLength(sh, sa);

        // Restore original EOF even if any step below throws.
        EofRestoreGuard eofGuard(sh, sf);

        std::vector<Extent> extended =
            GetExtents(sh);

        if (!SameExtents(streamExtents, extended)) {
            Fail(
                "ABORT: extending EOF changed the extent mapping."
            );
        }

        ZeroRange(sh, sf, sa - sf);

        if (!FlushFileBuffers(sh))
            ThrowWin32(
                L"FlushFileBuffers(after slack write)"
            );

        SetFileLength(sh, sf);

        if (!FlushFileBuffers(sh))
            ThrowWin32(
                L"FlushFileBuffers(after EOF restore)"
            );

        eofGuard.commit();
    }

    std::vector<Extent> afterWrite =
        GetExtents(sh);

    if (!SameExtents(streamExtents, afterWrite))
    {
        Fail(
            "WARNING/ABORT: extent mapping changed during wipe."
        );
    }

    streamExtents = afterWrite;

    if (sf == 0)
        return;

    if (!quiet)
        std::cout
            << "\nPost-write verification...\n";

    std::vector<BYTE> expectedZero =
        HashZeros(sf);

    std::vector<BYTE> normalAfter =
        HashFile(sh, sf);

    if (!opts.noVerify) {
        std::vector<BYTE> rawAfter =
            HashRawExtents(
                vc.volume.get(),
                afterWrite,
                vi.clusterSize,
                vi.bytesPerSector,
                sf
            );

        if (!quiet) {
            std::cout
                << "expected-zero SHA-256: "
                << Hex(expectedZero)
                << "\n"
                << "normal        SHA-256: "
                << Hex(normalAfter)
                << "\n"
                << "raw           SHA-256: "
                << Hex(rawAfter)
                << "\n";
        }

        if (rawAfter != expectedZero)
            Fail("FAIL: direct LCN read is not all-zero.");
    } else if (!quiet) {
        std::cout
            << "expected-zero SHA-256: "
            << Hex(expectedZero)
            << "\n"
            << "normal        SHA-256: "
            << Hex(normalAfter)
            << "\n";
    }

    if (normalAfter != expectedZero)
        Fail("FAIL: normal stream read is not all-zero.");

    if (wipeSlack) {
        if (!opts.noVerify) {
            std::vector<BYTE> expectedAllocationZero =
                HashZeros(sa);

            std::vector<BYTE> rawAllocation =
                HashRawExtents(
                    vc.volume.get(),
                    afterWrite,
                    vi.clusterSize,
                    vi.bytesPerSector,
                    sa
                );

            if (!quiet) {
                std::cout
                    << "full allocation zero SHA-256: "
                    << Hex(expectedAllocationZero)
                    << "\n"
                    << "full allocation raw  SHA-256: "
                    << Hex(rawAllocation)
                    << "\n";
            }

            if (rawAllocation != expectedAllocationZero)
                Fail(
                    "FAIL: allocated clusters including final slack "
                    "are not completely zero."
                );
        } else if (!quiet) {
            std::cout
                << "full-allocation raw verification skipped "
                << "(--no-verify).\n";
        }
    }
}

// delete-pending freeze: once armed, Windows rejects new CreateFile
// opens on this file, so no additional ADS can appear behind our
// back. Phase-B failures must call rollback() and check the result;
// the destructor is only best effort when the caller could not.
class DispositionGuard {
public:
    explicit DispositionGuard(HANDLE h) : h_(h) {}

    ~DispositionGuard() {
        if (armed_ && !committed_) {
            DWORD ignored = 0;
            rollback(ignored);
        }
    }

    DispositionGuard(const DispositionGuard&) = delete;
    DispositionGuard& operator=(const DispositionGuard&) = delete;

    // Returns false when Windows refused the delete-pending mark
    // (e.g. ERROR_DIR_NOT_EMPTY); *err is still valid.
    bool arm(DWORD& err) {
        FILE_DISPOSITION_INFO di{};
        di.DeleteFile = TRUE;

        if (!SetFileInformationByHandle(
                h_,
                FileDispositionInfo,
                &di,
                sizeof(di)))
        {
            err = GetLastError();
            return false;
        }

        armed_ = true;
        err = ERROR_SUCCESS;
        return true;
    }

    // Clears the disposition so handle close does not free the
    // object. Returns false when the rollback itself failed;
    // *err holds GetLastError() in that case (and is unchanged
    // on success except ERROR_SUCCESS).
    bool rollback(DWORD& err) {
        if (!armed_ || committed_) {
            err = ERROR_SUCCESS;
            return true;
        }

        FILE_DISPOSITION_INFO di{};
        di.DeleteFile = FALSE;

        if (!SetFileInformationByHandle(
                h_,
                FileDispositionInfo,
                &di,
                sizeof(di)))
        {
            err = GetLastError();
            return false;
        }

        armed_ = false;
        err = ERROR_SUCCESS;
        return true;
    }

    void disarm() {
        DWORD ignored = 0;
        rollback(ignored);
    }

    // Keep the delete-pending mark through handle close.
    void commit() {
        armed_ = false;
        committed_ = true;
    }

private:
    HANDLE h_;
    bool armed_ = false;
    bool committed_ = false;
};

// ------------------------------------------------------------
// Einzeldatei-Pipeline (aus wmain extrahiert)
// ------------------------------------------------------------

FileResult ProcessOneFile(
    const std::wstring& path,
    const Options& opts,
    VolumeContext& vc,
    uint64_t expectedFileId = 0)
{
    try {
        const bool wipe =
            opts.mode == Mode::Wipe ||
            opts.mode == Mode::WipeSlack;

        const bool wipeSlack =
            opts.mode == Mode::WipeSlack;

        const bool quiet =
            opts.recursive && !opts.verbose;

        // DELETE is requested for every wipe so the stream-set freeze
        // can be armed (including single-file wipes). Recursive modes
        // keep the disposition after success (atomic wipe+delete);
        // single-file wipes roll it back after a successful wipe.
        const bool wantDelete = wipe;
        const bool commitDelete = wipe && opts.recursive;

        DWORD pathAttrs =
            GetFileAttributesW(path.c_str());

        if (pathAttrs == INVALID_FILE_ATTRIBUTES)
            ThrowWin32(L"GetFileAttributesW");

        if (pathAttrs & FILE_ATTRIBUTE_DIRECTORY)
            Fail("Directories are not supported.");

        // Fast-path reject; the authoritative check is on the handle
        // after CreateFile with FILE_FLAG_OPEN_REPARSE_POINT below.
        if (pathAttrs & FILE_ATTRIBUTE_REPARSE_POINT) {
            return SkipOrFail(
                path,
                "Reparse points/symlinks are intentionally rejected.",
                opts
            );
        }

        DWORD wipeFlags = FILE_FLAG_OPEN_REPARSE_POINT;

        if (wipe)
            wipeFlags |= FILE_FLAG_WRITE_THROUGH;

        // --------------------------------------------------------
        // Discovery pass: shared read-only open, enumerate streams.
        // Named ADS live on the same file object, so the exclusive
        // wipe handle cannot fan out to them; discover first, then
        // open for real.
        // --------------------------------------------------------

        std::vector<StreamInfoEntry> streams;

        {
            HANDLE dh = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr
            );

            if (dh == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();

                if (opts.recursive &&
                    (err == ERROR_SHARING_VIOLATION ||
                     err == ERROR_LOCK_VIOLATION ||
                     err == ERROR_ACCESS_DENIED))
                {
                    return SkipOrFail(
                        path,
                        "Cannot open for discovery: " +
                            WideToUtf8(WinErrorText(err)),
                        opts
                    );
                }

                ThrowWin32(L"CreateFile(discovery)", err);
            }

            Handle discovery(dh);

            BY_HANDLE_FILE_INFORMATION bhi{};

            if (!GetFileInformationByHandle(
                    discovery.get(),
                    &bhi))
            {
                ThrowWin32(L"GetFileInformationByHandle");
            }

            // Pin identity from directory enumeration: a different
            // object under the same name must not be wiped.
            if (expectedFileId) {
                uint64_t openedId =
                    (static_cast<uint64_t>(bhi.nFileIndexHigh)
                     << 32) |
                    static_cast<uint64_t>(bhi.nFileIndexLow);

                if (openedId != expectedFileId) {
                    if (opts.recursive) {
                        return SkipOrFail(
                            path,
                            "file identity changed "
                            "(FileId mismatch after open)",
                            opts
                        );
                    }

                    Fail(
                        "file identity changed "
                        "(FileId mismatch after open)"
                    );
                }
            }

            std::string ineligible =
                ValidateCandidate(
                    bhi.dwFileAttributes,
                    bhi.nNumberOfLinks,
                    opts
                );

            if (!ineligible.empty()) {
                return SkipOrFail(
                    path,
                    std::move(ineligible),
                    opts
                );
            }

            streams = QueryStreams(discovery.get());
        }

        std::vector<StreamInfoEntry> named;

        for (const StreamInfoEntry& s : streams) {
            if (s.IsNamedData())
                named.push_back(s);
        }

        DWORD access =
            GENERIC_READ |
            (wipe ? GENERIC_WRITE : 0) |
            (wantDelete ? DELETE : 0);

        // Sharing modes are maintained per stream on NTFS. The default
        // stream stays exclusive even when named ADS exist. Named ADS
        // handles are exclusive for R/W on their own stream; they only
        // share DELETE when the default handle already holds DELETE
        // (existing access must be covered by the new open's share).
        DWORD share = 0;

        HANDLE fh = CreateFileW(
            path.c_str(),
            access,
            share,
            nullptr,
            OPEN_EXISTING,
            static_cast<DWORD>(wipeFlags),
            nullptr
        );

        if (fh == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();

            if (opts.recursive &&
                (err == ERROR_SHARING_VIOLATION ||
                 err == ERROR_LOCK_VIOLATION ||
                 err == ERROR_ACCESS_DENIED))
            {
                return SkipOrFail(
                    path,
                    "Cannot open exclusively: " +
                        WideToUtf8(WinErrorText(err)),
                    opts
                );
            }

            ThrowWin32(L"CreateFile(file)", err);
        }

        Handle file(fh);

        BY_HANDLE_FILE_INFORMATION bhi{};

        if (!GetFileInformationByHandle(
                file.get(),
                &bhi))
        {
            ThrowWin32(L"GetFileInformationByHandle");
        }

        // Second pin on the wipe handle itself (discovery may have
        // closed before a swap): never write through a mismatched id.
        if (expectedFileId) {
            uint64_t wipeId =
                (static_cast<uint64_t>(bhi.nFileIndexHigh) << 32) |
                static_cast<uint64_t>(bhi.nFileIndexLow);

            if (wipeId != expectedFileId) {
                if (opts.recursive) {
                    return SkipOrFail(
                        path,
                        "file identity changed "
                        "(FileId mismatch on wipe handle)",
                        opts
                    );
                }

                Fail(
                    "file identity changed "
                    "(FileId mismatch on wipe handle)"
                );
            }
        }

        DWORD attrs = bhi.dwFileAttributes;

        if (attrs & FILE_ATTRIBUTE_DIRECTORY)
            Fail("Directories are not supported.");

        // Handle-based checks: CreateFile opened with
        // FILE_FLAG_OPEN_REPARSE_POINT, so a swapped-in symlink/junction
        // is not followed and still shows FILE_ATTRIBUTE_REPARSE_POINT.
        std::string ineligible =
            ValidateCandidate(
                attrs,
                bhi.nNumberOfLinks,
                opts
            );

        if (!ineligible.empty()) {
            return SkipOrFail(
                path,
                std::move(ineligible),
                opts
            );
        }

        FILE_STANDARD_INFO standard{};

        if (!GetFileInformationByHandleEx(
                file.get(),
                FileStandardInfo,
                &standard,
                sizeof(standard)))
        {
            ThrowWin32(
                L"GetFileInformationByHandleEx(FileStandardInfo)"
            );
        }

        if (standard.EndOfFile.QuadPart < 0 ||
            standard.AllocationSize.QuadPart < 0)
        {
            Fail("Invalid negative file/allocation size.");
        }

        uint64_t fileSize =
            static_cast<uint64_t>(
                standard.EndOfFile.QuadPart
            );

        uint64_t allocationSize =
            static_cast<uint64_t>(
                standard.AllocationSize.QuadPart
            );

        // Resolve final target for visibility.
        if (!quiet) {
            wchar_t finalPath[32768]{};

            DWORD finalLen =
                GetFinalPathNameByHandleW(
                    file.get(),
                    finalPath,
                    static_cast<DWORD>(
                        std::size(finalPath)
                    ),
                    FILE_NAME_NORMALIZED
                );

            if (finalLen &&
                finalLen < std::size(finalPath))
            {
                std::wcout
                    << L"Target:      "
                    << finalPath
                    << L"\n";
            } else {
                std::wcout
                    << L"Target:      "
                    << path
                    << L"\n";
            }
        }

        std::string volError;

        if (!EnsureVolume(path, opts, vc, volError)) {
            if (!opts.recursive)
                Fail(volError);

            return SkipOrFail(path, volError, opts);
        }

        const VolumeInfo& vi = vc.info;

        // Re-query streams on the wipe handle: the set may have changed
        // since discovery (TOCTOU). Wiping happens only for streams
        // visible on this handle.
        streams = QueryStreams(file.get());
        named.clear();

        for (const StreamInfoEntry& s : streams) {
            if (s.IsNamedData())
                named.push_back(s);
        }

        // Named streams on an exclusive default handle: per-stream
        // sharing still allows opening path:stream, but a set that only
        // appeared after the exclusive open is refused (see below when
        // discovery saw none). Streams that existed at discovery and
        // are visible here are opened individually during preflight.

        // Skip FileAccess to unnamed default stream sizes: use the
        // FileStandardInfo values already collected for the default.
        bool defaultNonEmpty = fileSize > 0;

        if (!quiet && !named.empty()) {
            std::wcout
                << L"ADS streams:  "
                << named.size()
                << L"\n";
        }

        bool anyContent = defaultNonEmpty;

        for (const StreamInfoEntry& s : named) {
            if (s.size > 0)
                anyContent = true;
        }

        if (!quiet) {
            std::wcout
                << L"Volume:      "
                << vi.guidPath
                << L"\n"
                << L"File size:   "
                << fileSize
                << L" bytes\n"
                << L"Allocation:  "
                << allocationSize
                << L" bytes\n"
                << L"Sector:      "
                << vi.bytesPerSector
                << L" bytes\n"
                << L"Cluster:     "
                << vi.clusterSize
                << L" bytes\n";
        }

        // ----------------------------------------------------
        // Phase A (all streams, non-destructive): open every
        // named ADS, run stream eligibility + slack/extent
        // preflight + the normal-vs-raw SHA-256 check for every
        // stream. Runs before the empty-file decision so a
        // preallocated empty ADS is refused the same way the
        // dry-run reports it (parity with DryRunFile).
        // ----------------------------------------------------

        struct OpenNamed {
            StreamInfoEntry info;
            Handle h;
            std::vector<Extent> extents;
            uint64_t size = 0;
            uint64_t alloc = 0;
        };

        std::vector<OpenNamed> namedOpen;

        auto preflightNamed = [&]() {
            for (const StreamInfoEntry& s : named) {
                OpenNamed on;
                on.info = s;

                DWORD nAccess =
                    GENERIC_READ |
                    (wipe ? GENERIC_WRITE : 0);

                // Per-stream sharing: exclusive R/W on this ADS. Only
                // share DELETE when the default handle already holds
                // DELETE (existing access must be covered).
                DWORD nShare =
                    wantDelete ? FILE_SHARE_DELETE : 0;

                HANDLE nh = CreateFileW(
                    StreamOpenPath(path, s).c_str(),
                    nAccess,
                    nShare,
                    nullptr,
                    OPEN_EXISTING,
                    wipeFlags,
                    nullptr
                );

                if (nh == INVALID_HANDLE_VALUE) {
                    DWORD err = GetLastError();

                    if (opts.recursive &&
                        (err == ERROR_SHARING_VIOLATION ||
                         err == ERROR_LOCK_VIOLATION ||
                         err == ERROR_ACCESS_DENIED))
                    {
                        Fail(
                            "Cannot open ADS: " +
                                WideToUtf8(WinErrorText(err))
                        );
                    }

                    ThrowWin32(L"CreateFile(ADS)", err);
                }

                on.h = Handle(nh);

                // Compression/encryption/sparseness are per-stream
                // states: validate on the ADS handle itself.
                BY_HANDLE_FILE_INFORMATION nbhi{};

                if (!GetFileInformationByHandle(
                        on.h.get(),
                        &nbhi))
                {
                    ThrowWin32(L"GetFileInformationByHandle(ADS)");
                }

                std::string streamIneligible =
                    ValidateStreamCandidate(nbhi.dwFileAttributes);

                if (!streamIneligible.empty())
                    Fail(streamIneligible);

                FILE_STANDARD_INFO ns{};

                if (!GetFileInformationByHandleEx(
                        on.h.get(),
                        FileStandardInfo,
                        &ns,
                        sizeof(ns)))
                {
                    ThrowWin32(
                        L"GetFileInformationByHandleEx(FileStandardInfo, ADS)"
                    );
                }

                if (ns.EndOfFile.QuadPart < 0 ||
                    ns.AllocationSize.QuadPart < 0)
                {
                    Fail("Invalid negative ADS size.");
                }

                on.size =
                    static_cast<uint64_t>(ns.EndOfFile.QuadPart);
                on.alloc =
                    static_cast<uint64_t>(ns.AllocationSize.QuadPart);

                if (on.size > 0)
                    on.extents = GetExtents(on.h.get());

                // Slack / extent preconditions before any ZeroRange.
                PreflightStreamCompat(
                    on.size,
                    on.alloc,
                    on.extents,
                    "ADS",
                    wipeSlack,
                    vi.clusterSize
                );

                namedOpen.push_back(std::move(on));
            }
        };

        if (!named.empty()) {
            try {
                preflightNamed();
            }
            catch (const ResidentDataError&) {
                if (opts.recursive) {
                    return MakeResult(
                        path,
                        FileStatus::Unsupported,
                        "ADS stream is resident in the NTFS MFT; "
                        "file not wiped or deleted."
                    );
                }

                Fail(
                    "ADS stream is resident in the NTFS MFT; "
                    "file not wiped or deleted."
                );
            }
            catch (const std::exception&) {
                // Never wipe or dispose if an ADS cannot be prepared.
                throw;
            }
        }

        // ----------------------------------------------------
        // Default-stream extents + preflight size coverage.
        // ----------------------------------------------------

        std::vector<Extent> extents;

        if (defaultNonEmpty) {
            extents = GetExtents(file.get());

            if (!quiet) {
                if (opts.verbose) {
                    PrintExtents(
                        extents,
                        vi.clusterSize
                    );
                } else {
                    std::wcout
                        << L"Extents:     "
                        << extents.size()
                        << L" block(s)\n";
                }
            }

            uint64_t coveredBytes =
                static_cast<uint64_t>(
                    extents.back().vcnEnd
                ) * vi.clusterSize;

            if (coveredBytes < fileSize)
                Fail(
                    "VCN extents do not cover the entire logical file."
                );

            if (coveredBytes < allocationSize)
                Fail(
                    "VCN extents do not cover AllocationSize."
                );
        }

        // All-stream --wipe-slack precondition before the first
        // ZeroRange on any stream (including the default stream).
        if (defaultNonEmpty) {
            PreflightStreamCompat(
                fileSize,
                allocationSize,
                extents,
                "default stream",
                wipeSlack,
                vi.clusterSize
            );
        } else if (wipeSlack && allocationSize > 0) {
            // Empty default stream with preallocated clusters: slack
            // wipe cannot run; refuse before any ADS is wiped.
            PreflightStreamCompat(
                0,
                allocationSize,
                {},
                "default stream",
                wipeSlack,
                vi.clusterSize
            );
        }

        // Phase A continued: pre-write normal-vs-raw SHA-256 for
        // every stream (ADS first, then default). A mismatch on any
        // stream aborts before the first write of any stream.
        for (OpenNamed& on : namedOpen) {
            PreWriteVerifyStream(
                on.h.get(),
                on.size,
                on.extents,
                false,
                opts,
                vi,
                vc,
                quiet
            );
        }

        if (defaultNonEmpty) {
            PreWriteVerifyStream(
                file.get(),
                fileSize,
                extents,
                true,
                opts,
                vi,
                vc,
                quiet
            );
        }

        // Empty logical content: Phase A (ADS preflight + default
        // PreflightStreamCompat above) already refused preallocated
        // empty streams. Non-recursive empty fails like DryRunFile;
        // recursive wipe deletes via disposition after a freeze
        // re-check so content cannot appear behind our back.
        if (!anyContent) {
            if (!opts.recursive)
                Fail("Empty file: nothing to process.");

            if (commitDelete) {
                DispositionGuard emptyFreeze(file.get());
                DWORD armErr = 0;

                if (!emptyFreeze.arm(armErr)) {
                    ThrowWin32(
                        L"SetFileInformationByHandle(disposition)",
                        armErr
                    );
                }

                // Everything after a successful arm() until
                // commit()/rollback() runs under one checked handler:
                // QueryStreams/GetFileInformationByHandleEx can throw
                // outside a narrower Phase-B catch.
                try {
                    FILE_STANDARD_INFO nowStd{};

                    if (!GetFileInformationByHandleEx(
                            file.get(),
                            FileStandardInfo,
                            &nowStd,
                            sizeof(nowStd)))
                    {
                        ThrowWin32(
                            L"GetFileInformationByHandleEx"
                            L"(FileStandardInfo, frozen)"
                        );
                    }

                    std::vector<StreamInfoEntry> nowStreams =
                        QueryStreams(file.get());

                    bool grew =
                        nowStd.EndOfFile.QuadPart > 0 ||
                        static_cast<uint64_t>(
                            nowStd.AllocationSize.QuadPart
                        ) != allocationSize;

                    // Same set comparison as the non-empty freeze:
                    // a named $DATA that was not part of Phase A (or
                    // grew vs the Phase-A size/alloc snapshot) never
                    // went through PreflightStreamCompat — including
                    // a new empty ADS with AllocationSize > 0.
                    for (const StreamInfoEntry& s : nowStreams) {
                        if (!s.IsNamedData())
                            continue;

                        const OpenNamed* phaseA = nullptr;

                        for (const OpenNamed& on : namedOpen) {
                            if (on.info.cStreamName ==
                                s.cStreamName)
                            {
                                phaseA = &on;
                                break;
                            }
                        }

                        if (!phaseA) {
                            grew = true;
                            continue;
                        }

                        if (s.size != phaseA->size ||
                            s.allocSize != phaseA->alloc)
                        {
                            grew = true;
                        }
                    }

                    if (grew) {
                        Fail(
                            "content appeared after the delete-pending "
                            "freeze (file not wiped or deleted)."
                        );
                    }

                    emptyFreeze.commit();
                }
                catch (const std::exception& e) {
                    DWORD rbErr = 0;

                    if (!emptyFreeze.rollback(rbErr)) {
                        throw std::runtime_error(
                            std::string(e.what()) +
                            "; delete-pending rollback failed: " +
                            WideToUtf8(WinErrorText(rbErr))
                        );
                    }

                    throw;
                }
            }

            return MakeResult(
                path,
                FileStatus::Empty,
                "empty file: nothing to overwrite"
            );
        }

        // ----------------------------------------------------
        // Stream-set freeze: mark delete-pending before the first
        // write. Windows then rejects new CreateFile opens on this
        // file, so no additional ADS can be created/opened behind
        // our already-hashed stream set. Phase-B failures must call
        // rollback() and check the result; the destructor is only
        // best effort.
        // ----------------------------------------------------

        DispositionGuard freeze(file.get());

        if (wipe) {
            DWORD armErr = 0;

            if (!freeze.arm(armErr)) {
                Fail(
                    "Cannot mark delete-pending before wipe: " +
                        WideToUtf8(WinErrorText(armErr))
                );
            }

            // Single outer handler for everything after a successful
            // arm() until commit()/rollback(): the frozen-set
            // re-check (QueryStreams) and Phase B can both throw; a
            // failed rollback is reported with the original error.
            try {
                // The stream set must not grow after the freeze: any
                // named $DATA stream visible now that was not part of
                // Phase A cannot be opened anymore (delete-pending
                // rejects CreateFile) and must abort the run before
                // the first write.
                std::vector<StreamInfoEntry> frozenSet =
                    QueryStreams(file.get());

                for (const StreamInfoEntry& s : frozenSet) {
                    if (!s.IsNamedData())
                        continue;

                    bool known = false;

                    for (const OpenNamed& on : namedOpen) {
                        if (on.info.cStreamName == s.cStreamName) {
                            known = true;
                            break;
                        }
                    }

                    if (!known) {
                        Fail(
                            "ADS appeared after the delete-pending "
                            "freeze: " +
                                WideToUtf8(s.cStreamName) +
                                " (file not wiped or deleted)."
                        );
                    }
                }

                // Phase B (destructive): overwrite every stream, then
                // post-verify. All predictable checks already passed
                // in Phase A.
                for (OpenNamed& on : namedOpen) {
                    if (!quiet && !opts.verbose) {
                        std::wcout
                            << L"ADS:        "
                            << on.info.cStreamName
                            << L"  ("
                            << on.size
                            << L" bytes)\n";
                    }

                    WipeStreamPhaseB(
                        on.h.get(),
                        on.size,
                        on.alloc,
                        on.extents,
                        false,
                        opts,
                        vi,
                        vc,
                        quiet
                    );
                }

                // Default stream.
                if (defaultNonEmpty) {
                    WipeStreamPhaseB(
                        file.get(),
                        fileSize,
                        allocationSize,
                        extents,
                        true,
                        opts,
                        vi,
                        vc,
                        quiet
                    );
                }

                // Recursive: keep the delete-pending mark (atomic
                // wipe+delete). Single-file wipe: clear it so the
                // wiped file stays; a failed rollback is a hard
                // error.
                if (commitDelete) {
                    freeze.commit();
                } else {
                    DWORD rbErr = 0;

                    if (!freeze.rollback(rbErr)) {
                        Fail(
                            "Cannot clear delete-pending after wipe: " +
                                WideToUtf8(WinErrorText(rbErr))
                        );
                    }
                }
            }
            catch (const std::exception& e) {
                DWORD rbErr = 0;

                if (!freeze.rollback(rbErr)) {
                    throw std::runtime_error(
                        std::string(e.what()) +
                        "; delete-pending rollback failed: " +
                        WideToUtf8(WinErrorText(rbErr))
                    );
                }

                throw;
            }
        }

        if (!quiet) {
            if (!wipe)
                std::cout
                    << "\nRead-only verification completed successfully.\n";
            else if (opts.noVerify)
                std::cout
                    << "\nSUCCESS: overwrite completed "
                    << "(raw-LCN verification disabled).\n";
            else
                std::cout
                    << "\nSUCCESS: overwrite and raw-LCN verification passed.\n";
        }

        if (!wipe)
            return MakeResult(path, FileStatus::Verified);

        return MakeResult(path, FileStatus::Wiped);
    }
    catch (const ResidentDataError& e) {
        if (opts.recursive)
            return MakeResult(path, FileStatus::Unsupported, e.what());

        Fail(e.what());
    }
    catch (const std::exception& e) {
        if (opts.recursive)
            return MakeResult(path, FileStatus::Failed, e.what());

        throw;
    }
}

// Dry-run: same eligibility checks and the same open rights the real
// mode would use (including GENERIC_WRITE/DELETE for wipe modes), plus
// the NTFS volume check. Never writes or sets disposition.
FileResult DryRunFile(
    const std::wstring& path,
    const Options& opts,
    uint64_t expectedFileId = 0)
{
    try {
        DWORD pathAttrs =
            GetFileAttributesW(path.c_str());

        if (pathAttrs == INVALID_FILE_ATTRIBUTES)
            ThrowWin32(L"GetFileAttributesW");

        std::string ineligible =
            ValidateCandidate(
                pathAttrs,
                0,
                opts
            );

        const bool wipe =
            opts.mode == Mode::Wipe ||
            opts.mode == Mode::WipeSlack;

        // Match ProcessOneFile: DELETE is requested for every wipe so
        // the stream-set freeze can be armed (FileDispositionInfo
        // requires DELETE on that handle). Recursive modes would keep
        // the disposition; dry-run never writes or arms it.
        const bool wantDelete = wipe;

        if (ineligible.empty()) {
            // Match the real pipeline's access rights and share mode
            // so sharing/write/permission failures show up in dry-run.
            DWORD access =
                GENERIC_READ |
                (wipe ? GENERIC_WRITE : 0) |
                (wantDelete ? DELETE : 0);

            DWORD wipeFlags = FILE_FLAG_OPEN_REPARSE_POINT;

            if (wipe)
                wipeFlags |= FILE_FLAG_WRITE_THROUGH;

            HANDLE fh = CreateFileW(
                path.c_str(),
                access,
                0,
                nullptr,
                OPEN_EXISTING,
                wipeFlags,
                nullptr
            );

            if (fh == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();

                return MakeResult(
                    path,
                    FileStatus::Skipped,
                    "cannot open exclusively (same as real wipe): " +
                        WideToUtf8(WinErrorText(err))
                );
            }

            Handle file(fh);

            BY_HANDLE_FILE_INFORMATION bhi{};

            if (!GetFileInformationByHandle(
                    file.get(),
                    &bhi))
            {
                ThrowWin32(L"GetFileInformationByHandle");
            }

            if (expectedFileId) {
                uint64_t openedId =
                    (static_cast<uint64_t>(bhi.nFileIndexHigh)
                     << 32) |
                    static_cast<uint64_t>(bhi.nFileIndexLow);

                if (openedId != expectedFileId) {
                    return SkipOrFail(
                        path,
                        "file identity changed "
                        "(FileId mismatch after open)",
                        opts
                    );
                }
            }

            ineligible =
                ValidateCandidate(
                    bhi.dwFileAttributes,
                    bhi.nNumberOfLinks,
                    opts
                );

            if (ineligible.empty()) {
                FILE_STANDARD_INFO standard{};

                if (!GetFileInformationByHandleEx(
                        file.get(),
                        FileStandardInfo,
                        &standard,
                        sizeof(standard)))
                {
                    ThrowWin32(
                        L"GetFileInformationByHandleEx(FileStandardInfo)"
                    );
                }

                if (standard.EndOfFile.QuadPart < 0 ||
                    standard.AllocationSize.QuadPart < 0)
                {
                    Fail("Invalid negative file/allocation size.");
                }

                const uint64_t fileSize =
                    static_cast<uint64_t>(
                        standard.EndOfFile.QuadPart
                    );
                const uint64_t allocationSize =
                    static_cast<uint64_t>(
                        standard.AllocationSize.QuadPart
                    );

                // NTFS check first: the shared preflight below needs
                // the cluster size (same as the real pipeline).
                std::string volError;
                VolumeContext dryVc;
                dryVc.valid = false;
                Options dryOpts = opts;
                dryOpts.dryRun = true;

                if (!EnsureVolume(path, dryOpts, dryVc, volError)) {
                    return SkipOrFail(
                        path,
                        volError,
                        opts
                    );
                }

                const VolumeInfo& vi = dryVc.info;
                const bool wipeSlack =
                    opts.mode == Mode::WipeSlack;

                // Same resident-data / ADS detection as the real pipeline.
                std::vector<StreamInfoEntry> streams =
                    QueryStreams(file.get());

                bool anyContent = fileSize > 0;

                // Open every named ADS with the real pipeline's
                // rights and run the same stream eligibility +
                // PreflightStreamCompat checks (including the
                // AllocationSize slack precondition) so a dry-run
                // DRY result implies the real run can wipe.
                for (const StreamInfoEntry& s : streams) {
                    if (!s.IsNamedData())
                        continue;

                    if (s.size > 0)
                        anyContent = true;

                    HANDLE nh = CreateFileW(
                        StreamOpenPath(path, s).c_str(),
                        GENERIC_READ |
                            (wipe ? GENERIC_WRITE : 0),
                        wantDelete
                            ? FILE_SHARE_DELETE
                            : 0,
                        nullptr,
                        OPEN_EXISTING,
                        wipeFlags,
                        nullptr
                    );

                    if (nh == INVALID_HANDLE_VALUE) {
                        DWORD err = GetLastError();

                        return MakeResult(
                            path,
                            FileStatus::Skipped,
                            "cannot open ADS exclusively: " +
                                WideToUtf8(WinErrorText(err))
                        );
                    }

                    Handle ads(nh);

                    BY_HANDLE_FILE_INFORMATION nbhi{};

                    if (!GetFileInformationByHandle(
                            ads.get(),
                            &nbhi))
                    {
                        ThrowWin32(
                            L"GetFileInformationByHandle(ADS)"
                        );
                    }

                    std::string streamIneligible =
                        ValidateStreamCandidate(
                            nbhi.dwFileAttributes
                        );

                    if (!streamIneligible.empty()) {
                        if (opts.recursive) {
                            return MakeResult(
                                path,
                                FileStatus::Unsupported,
                                streamIneligible
                            );
                        }

                        Fail(streamIneligible);
                    }

                    FILE_STANDARD_INFO ns{};

                    if (!GetFileInformationByHandleEx(
                            ads.get(),
                            FileStandardInfo,
                            &ns,
                            sizeof(ns)))
                    {
                        ThrowWin32(
                            L"GetFileInformationByHandleEx"
                            L"(FileStandardInfo, ADS)"
                        );
                    }

                    if (ns.EndOfFile.QuadPart < 0 ||
                        ns.AllocationSize.QuadPart < 0)
                    {
                        Fail("Invalid negative ADS size.");
                    }

                    const uint64_t adSize =
                        static_cast<uint64_t>(
                            ns.EndOfFile.QuadPart
                        );
                    const uint64_t adAlloc =
                        static_cast<uint64_t>(
                            ns.AllocationSize.QuadPart
                        );

                    std::vector<Extent> adExtents;

                    if (adSize > 0)
                        adExtents = GetExtents(ads.get());

                    // Same eligibility preflight as the real run:
                    // this is what makes a DRY result trustworthy
                    // for --wipe-slack (e.g. preallocated empty
                    // streams are refused here as well).
                    PreflightStreamCompat(
                        adSize,
                        adAlloc,
                        adExtents,
                        "ADS",
                        wipeSlack,
                        vi.clusterSize
                    );
                }

                if (!anyContent) {
                    if (wipeSlack && allocationSize > 0) {
                        PreflightStreamCompat(
                            0,
                            allocationSize,
                            {},
                            "default stream",
                            wipeSlack,
                            vi.clusterSize
                        );
                    }

                    if (!opts.recursive)
                        Fail("Empty file: nothing to process.");

                    return MakeResult(
                        path,
                        FileStatus::Empty,
                        "empty file: nothing to overwrite"
                    );
                }

                std::vector<Extent> extents;

                if (fileSize > 0)
                    extents = GetExtents(file.get());

                PreflightStreamCompat(
                    fileSize,
                    allocationSize,
                    extents,
                    "default stream",
                    wipeSlack,
                    vi.clusterSize
                );
            }
        }

        if (!ineligible.empty()) {
            return SkipOrFail(
                path,
                std::move(ineligible),
                opts
            );
        }

        if (opts.mode == Mode::Verify)
            return MakeResult(path, FileStatus::WouldVerify);

        return MakeResult(path, FileStatus::WouldWipe);
    }
    catch (const ResidentDataError& e) {
        if (opts.recursive)
            return MakeResult(path, FileStatus::Unsupported, e.what());

        Fail(e.what());
    }
    catch (const std::exception& e) {
        if (opts.recursive)
            return MakeResult(path, FileStatus::Failed, e.what());

        throw;
    }
}

// ------------------------------------------------------------
// Rekursiver Ordner-Durchlauf
// ------------------------------------------------------------

std::wstring JoinPath(const std::wstring& dir, const wchar_t* name)
{
    std::wstring out = dir;

    if (!out.empty() && out.back() != L'\\')
        out.push_back(L'\\');

    out += name;
    return out;
}

const wchar_t* StatusTag(FileStatus s)
{
    switch (s) {
    case FileStatus::Verified:    return L"VERIFY-OK";
    case FileStatus::Wiped:       return L"WIPED";
    case FileStatus::Empty:       return L"EMPTY";
    case FileStatus::Skipped:     return L"SKIP";
    case FileStatus::Unsupported: return L"UNSUPPORTED";
    case FileStatus::Failed:      return L"FAIL";
    case FileStatus::WouldWipe:   return L"DRY";
    case FileStatus::WouldVerify: return L"DRY-VERIFY";
    }

    return L"?";
}

std::wstring DisplayPath(const std::wstring& p)
{
    if (p.rfind(L"\\\\?\\UNC\\", 0) == 0)
        return L"\\\\" + p.substr(8);

    if (p.rfind(L"\\\\?\\", 0) == 0)
        return p.substr(4);

    return p;
}

void PrintResult(const FileResult& r)
{
    std::wcout
        << StatusTag(r.status)
        << L"  "
        << DisplayPath(r.path)
        << L"\n";

    if (!r.message.empty())
        std::cout
            << "       "
            << r.message
            << "\n";
}

// Find* search handles must not appear here; directory walk uses
// GetFileInformationByHandleEx on a CreateFile handle (CloseHandle).

// ------------------------------------------------------------
// Race-resistant directory walk (handle-based enumeration)
// ------------------------------------------------------------

struct DirEntryInfo {
    std::wstring name;
    DWORD attributes = 0;
    uint64_t size = 0;
    // File reference number from FILE_ID_BOTH_DIR_INFO: used to pin
    // the child identity after reopen (swap of name → different object).
    uint64_t fileId = 0;
};

// File reference numbers from FILE_ID_BOTH_DIR_INFO are used to pin
// child identity after reopen (name swap → different object).

// Enumerate one directory via GetFileInformationByHandleEx so the
// listing is tied to an open directory object, not to a path that
// could be junction-swapped between FindFirstFile and CreateFile.
// Returns false on ERROR_NO_MORE_FILES (clean end) or on error
// (error is set); never parses a buffer from a failed call.
bool NextDirBatch(
    HANDLE dir,
    bool& restart,
    std::vector<BYTE>& buffer,
    std::vector<DirEntryInfo>& out,
    DWORD& error)
{
    FILE_INFO_BY_HANDLE_CLASS cls =
        restart
            ? FileIdBothDirectoryRestartInfo
            : FileIdBothDirectoryInfo;

    out.clear();

    for (;;) {
        BOOL ok = GetFileInformationByHandleEx(
            dir,
            cls,
            buffer.data(),
            static_cast<DWORD>(buffer.size())
        );

        if (ok)
            break;

        error = GetLastError();

        // Documented: the buffer is only valid on success. Grow and
        // retry — never parse structures from a failed call.
        if (error == ERROR_MORE_DATA) {
            if (buffer.size() >= (16 * 1024 * 1024))
                return false;

            buffer.resize(buffer.size() * 2);
            continue;
        }

        if (error == ERROR_NO_MORE_FILES)
            return false;

        return false;
    }

    restart = false;

    DWORD offset = 0;

    for (;;) {
        if (offset + FIELD_OFFSET(FILE_ID_BOTH_DIR_INFO, FileName) >
            buffer.size())
        {
            break;
        }

        auto* e = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(
            buffer.data() + offset
        );

        size_t nameBytes = e->FileNameLength;
        size_t entryMin =
            FIELD_OFFSET(FILE_ID_BOTH_DIR_INFO, FileName) + nameBytes;

        if (offset + entryMin > buffer.size())
            break;

        DirEntryInfo info;
        info.name.assign(
            e->FileName,
            nameBytes / sizeof(wchar_t)
        );
        info.attributes = e->FileAttributes;
        info.size =
            static_cast<uint64_t>(e->EndOfFile.QuadPart);
        info.fileId =
            static_cast<uint64_t>(e->FileId.QuadPart);
        out.push_back(std::move(info));

        if (e->NextEntryOffset == 0)
            break;

        offset += e->NextEntryOffset;
    }

    error = ERROR_SUCCESS;
    return true;
}

// Open a directory for handle-based enumeration. Always uses
// FILE_FLAG_OPEN_REPARSE_POINT so a swapped-in junction is observed
// as a reparse point instead of being traversed.
// *gotDelete is set when the handle was opened with DELETE access
// (required for FileDispositionInfo-based directory removal).
HANDLE OpenDirectoryForWalk(
    const std::wstring& dir,
    DWORD& err,
    bool* gotDelete = nullptr)
{
    if (gotDelete)
        *gotDelete = false;

    HANDLE h = CreateFileW(
        dir.c_str(),
        FILE_LIST_DIRECTORY | DELETE |
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE) {
        err = GetLastError();

        // DELETE is only needed for disposition-based removal; retry
        // without write/DELETE attributes for read-only walks.
        h = CreateFileW(
            dir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr
        );

        if (h == INVALID_HANDLE_VALUE) {
            err = GetLastError();
            return INVALID_HANDLE_VALUE;
        }

        err = ERROR_SUCCESS;
    } else {
        if (gotDelete)
            *gotDelete = true;

        err = ERROR_SUCCESS;
    }

    return h;
}

void WalkDirectoryHandle(
    const std::wstring& dir,
    Handle& dirHandle,
    bool dirHasDelete,
    const Options& opts,
    VolumeContext& vc,
    std::vector<FileResult>& results,
    uint64_t& dirsRemoved);

void WalkDirectoryHandle(
    const std::wstring& dir,
    Handle& dirHandle,
    bool dirHasDelete,
    const Options& opts,
    VolumeContext& vc,
    std::vector<FileResult>& results,
    uint64_t& dirsRemoved)
{
    // Authoritative: reparse check on the handle, not on find data.
    BY_HANDLE_FILE_INFORMATION dhi{};

    if (!GetFileInformationByHandle(
            dirHandle.get(),
            &dhi))
    {
        ThrowWin32(L"GetFileInformationByHandle(directory)");
    }

    if (dhi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        FileResult skip = MakeResult(
            dir,
            FileStatus::Skipped,
            "reparse point: not followed"
        );
        results.push_back(skip);
        PrintResult(skip);
        return;
    }

    std::vector<BYTE> buffer(64 * 1024);
    std::vector<DirEntryInfo> entries;
    bool restart = true;
    DWORD enumErr = ERROR_SUCCESS;
    bool enumerationFailed = false;

    for (;;) {
        bool more = NextDirBatch(
            dirHandle.get(),
            restart,
            buffer,
            entries,
            enumErr
        );

        if (!more) {
            if (enumErr != ERROR_SUCCESS &&
                enumErr != ERROR_NO_MORE_FILES)
            {
                enumerationFailed = true;
            }

            break;
        }

        for (const DirEntryInfo& e : entries) {
            if (e.name == L"." || e.name == L"..")
                continue;

            const std::wstring full = JoinPath(dir, e.name.c_str());

            // Never follow reparse points (junctions, symlinks, mounts).
            // Additionally confirmed on each child's own handle below.
            if (e.attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                FileResult skip = MakeResult(
                    full,
                    FileStatus::Skipped,
                    "reparse point: not followed"
                );
                results.push_back(skip);
                PrintResult(skip);
                continue;
            }

            if (e.attributes & FILE_ATTRIBUTE_DIRECTORY) {
                DWORD childErr = ERROR_SUCCESS;
                bool childDelete = false;
                Handle child(
                    OpenDirectoryForWalk(full, childErr, &childDelete)
                );

                if (!child.valid()) {
                    FileResult skip = MakeResult(
                        full,
                        FileStatus::Skipped,
                        "cannot open subdirectory: " +
                            WideToUtf8(WinErrorText(childErr))
                    );
                    results.push_back(skip);
                    PrintResult(skip);
                    continue;
                }

                BY_HANDLE_FILE_INFORMATION chi{};

                if (!GetFileInformationByHandle(
                        child.get(),
                        &chi))
                {
                    ThrowWin32(
                        L"GetFileInformationByHandle(subdirectory)"
                    );
                }

                // The handle was opened with OPEN_REPARSE_POINT: a
                // junction swapped in after the parent listing is seen
                // here and never traversed.
                if (chi.dwFileAttributes &
                    FILE_ATTRIBUTE_REPARSE_POINT)
                {
                    FileResult skip = MakeResult(
                        full,
                        FileStatus::Skipped,
                        "reparse point: not followed"
                    );
                    results.push_back(skip);
                    PrintResult(skip);
                    continue;
                }

                // Pin identity: a different object swapped in under
                // the same name must not be traversed.
                uint64_t childId =
                    (static_cast<uint64_t>(
                         chi.nFileIndexHigh
                     ) << 32) |
                    static_cast<uint64_t>(chi.nFileIndexLow);

                if (e.fileId && childId != e.fileId) {
                    FileResult skip = MakeResult(
                        full,
                        FileStatus::Skipped,
                        "directory identity changed "
                        "(FileId mismatch after open)"
                    );
                    results.push_back(skip);
                    PrintResult(skip);
                    continue;
                }

                // Recurse on the already-open child handle: no path
                // re-resolution between the reparse check and the walk.
                WalkDirectoryHandle(
                    full,
                    child,
                    childDelete,
                    opts,
                    vc,
                    results,
                    dirsRemoved
                );
                continue;
            }

            if (opts.dryRun) {
                FileResult r = DryRunFile(full, opts, e.fileId);
                results.push_back(r);
                PrintResult(results.back());
                continue;
            }

            FileResult r =
                ProcessOneFile(full, opts, vc, e.fileId);

            // Wipe+delete is atomic on the file handle inside
            // ProcessOneFile (FileDispositionInfo after verify).
            // Never DeleteFile by path here — that reopens a race.

            results.push_back(r);
            PrintResult(r);
        }
    }

    if (enumerationFailed) {
        results.push_back(MakeResult(
            dir,
            FileStatus::Skipped,
            "directory enumeration failed: " +
                WideToUtf8(WinErrorText(enumErr))
        ));
    }

    // Bottom-up: wipe the directory's own named $DATA streams, then
    // remove the directory if empty (wipe modes only). Directories
    // have no unnamed default $DATA, but MS-FSCC allows named $DATA
    // streams on directories — those must be overwritten before the
    // directory is marked for deletion. Non-$DATA streams such as
    // $INDEX_ALLOCATION are filtered by IsNamedData().
    // Removal only via FileDispositionInfo on this already-open
    // handle — never RemoveDirectoryW by path (TOCTOU race).
    //
    // Phase A (open + eligibility + slack/extent preflight) also runs
    // in dry-run so a DRY result implies the real run can wipe the
    // directory ADS. Freeze / Phase B / disposition stay real-only.
    if (opts.mode != Mode::Verify) {
        const bool wipeSlack =
            opts.mode == Mode::WipeSlack;
        const bool quiet =
            opts.recursive && !opts.verbose;
        const VolumeInfo& vi = vc.info;

        struct OpenDirStream {
            StreamInfoEntry info;
            Handle h;
            std::vector<Extent> extents;
            uint64_t size = 0;
            uint64_t alloc = 0;
        };

        std::vector<OpenDirStream> dirNamedOpen;

        // ----------------------------------------------------
        // Phase A for directory ADS: open + eligibility +
        // slack/extent preflight + pre-write hashes. No write,
        // no disposition yet.
        // ----------------------------------------------------
        try {
            for (const StreamInfoEntry& s :
                 QueryStreams(dirHandle.get()))
            {
                if (!s.IsNamedData())
                    continue;

                OpenDirStream on;
                on.info = s;

                DWORD nAccess =
                    GENERIC_READ | GENERIC_WRITE;

                // Mirror the file-ADS share rule: cover DELETE on
                // this open only when the directory handle already
                // holds DELETE (existing access must be covered).
                DWORD nShare =
                    dirHasDelete ? FILE_SHARE_DELETE : 0;

                DWORD flags =
                    FILE_FLAG_BACKUP_SEMANTICS |
                    FILE_FLAG_OPEN_REPARSE_POINT |
                    FILE_FLAG_WRITE_THROUGH;

                HANDLE nh = CreateFileW(
                    StreamOpenPath(dir, s).c_str(),
                    nAccess,
                    nShare,
                    nullptr,
                    OPEN_EXISTING,
                    flags,
                    nullptr
                );

                if (nh == INVALID_HANDLE_VALUE) {
                    // NTFS sharing is per stream: a sharing failure is
                    // a valuable "someone else holds this stream"
                    // signal. Never retry with a wider share mode.
                    DWORD err = GetLastError();
                    Fail(
                        "Cannot open directory ADS: " +
                            WideToUtf8(WinErrorText(err))
                    );
                }

                on.h = Handle(nh);

                BY_HANDLE_FILE_INFORMATION nbhi{};

                if (!GetFileInformationByHandle(
                        on.h.get(),
                        &nbhi))
                {
                    ThrowWin32(
                        L"GetFileInformationByHandle(directory ADS)"
                    );
                }

                std::string streamIneligible =
                    ValidateStreamCandidate(nbhi.dwFileAttributes);

                if (!streamIneligible.empty())
                    Fail(streamIneligible);

                FILE_STANDARD_INFO ns{};

                if (!GetFileInformationByHandleEx(
                        on.h.get(),
                        FileStandardInfo,
                        &ns,
                        sizeof(ns)))
                {
                    ThrowWin32(
                        L"GetFileInformationByHandleEx"
                        L"(FileStandardInfo, directory ADS)"
                    );
                }

                if (ns.EndOfFile.QuadPart < 0 ||
                    ns.AllocationSize.QuadPart < 0)
                {
                    Fail("Invalid negative directory ADS size.");
                }

                on.size =
                    static_cast<uint64_t>(ns.EndOfFile.QuadPart);
                on.alloc =
                    static_cast<uint64_t>(ns.AllocationSize.QuadPart);

                if (on.size > 0)
                    on.extents = GetExtents(on.h.get());

                PreflightStreamCompat(
                    on.size,
                    on.alloc,
                    on.extents,
                    "directory ADS",
                    wipeSlack,
                    vi.clusterSize
                );

                dirNamedOpen.push_back(std::move(on));
            }

            // Pre-write hashes need the raw volume handle, which dry
            // never opens; eligibility + PreflightStreamCompat above
            // are the dry-parity subset (same as DryRunFile).
            if (!opts.dryRun) {
                for (OpenDirStream& on : dirNamedOpen) {
                    PreWriteVerifyStream(
                        on.h.get(),
                        on.size,
                        on.extents,
                        false,
                        opts,
                        vi,
                        vc,
                        quiet
                    );
                }
            }
        }
        catch (const ResidentDataError& e) {
            FileResult unsup = MakeResult(
                dir,
                FileStatus::Unsupported,
                std::string(
                    "directory ADS is resident in the NTFS MFT; "
                    "directory not wiped or deleted: "
                ) + e.what()
            );
            results.push_back(unsup);
            PrintResult(unsup);
            return;
        }
        catch (const std::exception& e) {
            FileResult fail = MakeResult(
                dir,
                FileStatus::Failed,
                std::string(
                    "directory ADS preflight failed; "
                    "directory not deleted: "
                ) + e.what()
            );
            results.push_back(fail);
            PrintResult(fail);
            return;
        }

        // No DELETE on the directory handle: dirFreeze.arm() can never
        // succeed, so directory ADS must not be overwritten (Phase B
        // requires a successful stream-set freeze). Same Skipped in dry
        // and real runs — a WouldWipe here would not match Partial
        // Success later.
        if (!dirHasDelete) {
            FileResult skip = MakeResult(
                dir,
                FileStatus::Skipped,
                "no DELETE access on directory; "
                "directory ADS left in place"
            );
            results.push_back(skip);
            PrintResult(skip);
            return;
        }

        if (opts.dryRun) {
            // Dry never arms a freeze or removes the directory. Report
            // directory ADS that would be wiped so the validation
            // above is visible in the DRY summary.
            if (!dirNamedOpen.empty()) {
                FileResult dry = MakeResult(
                    dir,
                    FileStatus::WouldWipe,
                    "directory ADS would be wiped"
                );
                results.push_back(dry);
                PrintResult(dry);
            }

            return;
        }

        // ----------------------------------------------------
        // Stream-set freeze: arm delete-pending before the first
        // directory-ADS write so no new named $DATA can appear.
        // Fails with ERROR_DIR_NOT_EMPTY when skipped children
        // remain — then no deletion happens anyway below.
        // Reaching this point implies dirHasDelete (see skip above).
        // ----------------------------------------------------
        DispositionGuard dirFreeze(dirHandle.get());
        DWORD dirArmErr = 0;

        // Arm even when no directory ADS was found: the freeze also
        // blocks a new named $DATA from appearing between the stream
        // query and the disposition below. A failed arm aborts before
        // Phase B: no directory ADS is written without a successful
        // stream-set freeze.
        if (dirFreeze.arm(dirArmErr)) {
            // armed
        } else if (dirArmErr == ERROR_DIR_NOT_EMPTY) {
            FileResult skip = MakeResult(
                dir,
                FileStatus::Skipped,
                "directory not empty (skipped files remain); "
                "directory ADS left in place"
            );
            results.push_back(skip);
            PrintResult(skip);
            return;
        } else {
            FileResult fail = MakeResult(
                dir,
                FileStatus::Failed,
                "Cannot mark delete-pending before directory "
                "ADS wipe: " +
                    WideToUtf8(WinErrorText(dirArmErr))
            );
            results.push_back(fail);
            PrintResult(fail);
            return;
        }

        // Single outer handler after arm() until commit()/rollback():
        // the frozen-set re-check (QueryStreams) can throw outside a
        // narrower Phase-B catch, and a failed re-check must not skip
        // the checked rollback.
        try {
            // Re-query after the freeze: a named $DATA stream that
            // was not opened in Phase A cannot be wiped anymore (new
            // opens are rejected) — abort before the first write.
            for (const StreamInfoEntry& s :
                 QueryStreams(dirHandle.get()))
            {
                if (!s.IsNamedData())
                    continue;

                bool known = false;

                for (const OpenDirStream& on : dirNamedOpen) {
                    if (on.info.cStreamName == s.cStreamName) {
                        known = true;
                        break;
                    }
                }

                if (!known) {
                    Fail(
                        "directory ADS appeared after the "
                        "delete-pending freeze: " +
                            WideToUtf8(s.cStreamName) +
                            " (directory not wiped or deleted)."
                    );
                }
            }

            // Phase B: overwrite every directory ADS, then keep the
            // freeze as the disposition.
            try {
                for (OpenDirStream& on : dirNamedOpen) {
                    if (!quiet && !opts.verbose) {
                        std::wcout
                            << L"DIR-ADS:    "
                            << on.info.cStreamName
                            << L"  ("
                            << on.size
                            << L" bytes)\n";
                    }

                    WipeStreamPhaseB(
                        on.h.get(),
                        on.size,
                        on.alloc,
                        on.extents,
                        false,
                        opts,
                        vi,
                        vc,
                        quiet
                    );
                }
            }
            catch (const std::exception& e) {
                throw std::runtime_error(
                    std::string(
                        "directory ADS wipe failed; "
                        "directory not deleted: "
                    ) + e.what()
                );
            }

            dirFreeze.commit();
            ++dirsRemoved;
        }
        catch (const std::exception& e) {
            // Explicit checked rollback: the directory must not be
            // freed with unwiped streams; a failed rollback is part
            // of the reported error (destructor is only best effort).
            DWORD rbErr = 0;
            std::string msg(e.what());

            if (!dirFreeze.rollback(rbErr)) {
                msg += "; delete-pending rollback failed: " +
                    WideToUtf8(WinErrorText(rbErr));
            }

            FileResult fail = MakeResult(
                dir,
                FileStatus::Failed,
                msg
            );
            results.push_back(fail);
            PrintResult(fail);
            return;
        }
    }
}

struct TreeStats {
    uint64_t files = 0;
    uint64_t bytes = 0;
    uint64_t dirs = 0;
};

void CountTree(const std::wstring& dir, TreeStats& st)
{
    WIN32_FIND_DATAW fd{};

    std::wstring pat = dir;

    if (!pat.empty() && pat.back() != L'\\')
        pat.push_back(L'\\');

    pat += L"*";

    HANDLE raw = FindFirstFileExW(
        pat.c_str(),
        FindExInfoBasic,
        &fd,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH
    );

    FindHandle search(raw);

    if (!search.valid()) {
        DWORD err = GetLastError();

        if (err != ERROR_FILE_NOT_FOUND &&
            err != ERROR_PATH_NOT_FOUND)
        {
            // Surface real enumeration errors instead of silently
            // treating them as an empty tree.
            ThrowWin32(L"FindFirstFileExW", err);
        }

        return;
    }

    bool first = true;

    for (;;) {
        if (!first) {
            if (!FindNextFileW(search.get(), &fd)) {
                DWORD err = GetLastError();

                if (err != ERROR_NO_MORE_FILES)
                    ThrowWin32(L"FindNextFileW", err);

                break;
            }
        }

        first = false;

        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0)
        {
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ++st.dirs;
            CountTree(JoinPath(dir, fd.cFileName), st);
            continue;
        }

        ++st.files;

        ULARGE_INTEGER size{};
        size.LowPart = fd.nFileSizeLow;
        size.HighPart = fd.nFileSizeHigh;
        st.bytes += size.QuadPart;
    }
}

std::wstring ToExtendedPath(const std::wstring& p)
{
    if (p.rfind(L"\\\\?\\", 0) == 0)
        return p;

    wchar_t buffer[32768]{};

    DWORD n = GetFullPathNameW(
        p.c_str(),
        static_cast<DWORD>(std::size(buffer)),
        buffer,
        nullptr
    );

    if (!n || n >= std::size(buffer))
        return p;

    std::wstring abs(buffer, n);

    if (abs.rfind(L"\\\\", 0) == 0)
        return L"\\\\?\\UNC\\" + abs.substr(2);

    return L"\\\\?\\" + abs;
}

void PrintSummary(
    const std::vector<FileResult>& results,
    uint64_t dirsRemoved,
    const Options& opts)
{
    uint64_t wiped = 0;
    uint64_t verified = 0;
    uint64_t empty = 0;
    uint64_t skipped = 0;
    uint64_t unsupported = 0;
    uint64_t failed = 0;
    uint64_t wouldWipe = 0;

    for (const FileResult& r : results) {
        switch (r.status) {
        case FileStatus::Wiped:       ++wiped;       break;
        case FileStatus::Verified:    ++verified;    break;
        case FileStatus::Empty:       ++empty;       break;
        case FileStatus::Skipped:     ++skipped;     break;
        case FileStatus::Unsupported: ++unsupported; break;
        case FileStatus::Failed:      ++failed;      break;
        case FileStatus::WouldWipe:   ++wouldWipe;   break;
        case FileStatus::WouldVerify: ++wouldWipe;   break;
        }
    }

    std::wcout
        << L"------------------------------------------------------------\n";

    if (opts.dryRun) {
        if (opts.mode == Mode::Verify) {
            std::wcout
                << L"Dry run - no changes were made.\n"
                << L"Would verify:       "
                << wouldWipe
                << L" file(s)\n"
                << L"Would skip:         "
                << skipped
                << L"\n"
                << L"Unsupported:        "
                << unsupported
                << L"\n"
                << L"Empty:              "
                << empty
                << L"\n";
        } else {
            std::wcout
                << L"Dry run - no changes were made.\n"
                << L"Would wipe/delete: "
                << wouldWipe
                << L" file(s)\n"
                << L"Would skip:        "
                << skipped
                << L"\n"
                << L"Unsupported:       "
                << unsupported
                << L"\n"
                << L"Empty:             "
                << empty
                << L"\n";
        }
    } else {
            const wchar_t* emptyLabel =
            (opts.mode == Mode::Verify)
                ? L"Empty:               "
                : L"Empty (deleted):     ";

        std::wcout
            << L"Wiped:               " << wiped << L"\n"
            << L"Verified:            " << verified << L"\n"
            << emptyLabel << empty << L"\n"
            << L"Skipped:             " << skipped << L"\n"
            << L"Unsupported:         " << unsupported << L"\n"
            << L"Failed:              " << failed << L"\n"
            << L"Directories removed: " << dirsRemoved << L"\n";
    }

    std::wcout
        << L"------------------------------------------------------------\n";
}

// Exit codes: 0 = fully completed (everything requested was
// wiped/verified), 1 = partial (any skip, unsupported or failure
// remains — content may still exist), 2 = invalid command line.
int ExitCodeFromResults(const std::vector<FileResult>& results)
{
    for (const FileResult& r : results) {
        switch (r.status) {
        case FileStatus::Skipped:
        case FileStatus::Unsupported:
        case FileStatus::Failed:
            return 1;
        default:
            break;
        }
    }

    return 0;
}

bool ConfirmRecursive(const TreeStats& st, const Options& opts)
{
    if (opts.mode == Mode::Verify) {
        std::wcout
            << L"About to verify (read-only):\n"
            << L"  files:      " << st.files << L"\n"
            << L"  directories: " << st.dirs << L"\n"
            << L"  total size: " << st.bytes << L" bytes\n"
            << L"Proceed? [y/N] ";
    } else if (opts.mode == Mode::WipeSlack) {
        std::wcout
            << L"About to wipe (including cluster slack) and delete:\n"
            << L"  files:      " << st.files << L"\n"
            << L"  directories: " << st.dirs << L"\n"
            << L"  total size: " << st.bytes << L" bytes\n"
            << L"Proceed? [y/N] ";
    } else {
        std::wcout
            << L"About to wipe and delete:\n"
            << L"  files:      " << st.files << L"\n"
            << L"  directories: " << st.dirs << L"\n"
            << L"  total size: " << st.bytes << L" bytes\n"
            << L"Proceed? [y/N] ";
    }

    std::wstring line;
    std::getline(std::wcin, line);

    return
        line == L"y" || line == L"Y" ||
        line == L"yes" || line == L"Yes" ||
        line == L"YES" ||
        line == L"j" || line == L"J" ||
        line == L"ja" || line == L"Ja" ||
        line == L"JA";
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int wmain(int argc, wchar_t** argv)
{
    try {
        Options opts;
        std::wstring mode;
        std::wstring path;

        for (int i = 1; i < argc; ++i) {
            const std::wstring arg = argv[i];

            if (arg == L"-v" || arg == L"--verbose") {
                opts.verbose = true;
                continue;
            }

            if (arg == L"-r" || arg == L"--recursive") {
                opts.recursive = true;
                continue;
            }

            if (arg == L"--no-verify") {
                opts.noVerify = true;
                continue;
            }

            if (arg == L"--dry-run") {
                opts.dryRun = true;
                continue;
            }

            if (arg == L"-y" || arg == L"--yes") {
                opts.yes = true;
                continue;
            }

            if (arg == L"--verify" ||
                arg == L"--wipe" ||
                arg == L"--wipe-slack")
            {
                if (!mode.empty()) {
                    std::wcerr << L"Only one mode may be specified.\n";
                    return 2;
                }

                mode = arg;
                continue;
            }

            if (!arg.empty() && arg[0] == L'-') {
                std::wcerr
                    << L"Unknown option: "
                    << arg
                    << L"\n";
                return 2;
            }

            if (!path.empty()) {
                std::wcerr << L"Only one path may be specified.\n";
                return 2;
            }

            path = arg;
        }

        if (mode.empty() || path.empty()) {
            std::wcerr
                << L"Usage:\n\n"
                << L"  vcnwipe [--verify|--wipe|--wipe-slack] [-r|--recursive]\n"
                << L"          [--no-verify] [--dry-run] [-y|--yes]\n"
                << L"          [-v|--verbose] <file|directory>\n\n"
                << L"--verify      read-only verification\n"
                << L"--wipe        zero logical file contents\n"
                << L"--wipe-slack  additionally zero slack in final allocated cluster\n"
                << L"-r, recursive wipe files inside a directory, then delete\n"
                << L"              files and directories (reparse points are never followed)\n"
                << L"--no-verify   skip raw-LCN verification (no Administrator needed)\n"
                << L"--dry-run     only list what would be wiped/deleted\n"
                << L"              (same eligibility checks and open rights as the real run;\n"
                << L"               with --verify: list what would be verified)\n"
                << L"-y, --yes     skip the confirmation prompt for directories\n"
                << L"-v, verbose   print VCN->LCN block list\n\n"
                << L"Limitations:\n"
                << L"  Small files (or streams) resident in the NTFS MFT have no\n"
                << L"  LCN extents and cannot be wiped (reported as UNSUPPORTED).\n"
                << L"  All NTFS $DATA streams (including named ADS on files and\n"
                << L"  directories) are wiped; if any stream is resident/\n"
                << L"  unsupported, the file or directory is not deleted.\n"
                << L"  Raw-LCN verification only proves that the currently\n"
                << L"  allocated clusters read back as zero. It does not prove\n"
                << L"  that older copies no longer exist in SSD flash cells,\n"
                << L"  storage firmware, snapshots, backups, or other layers.\n\n"
                << L"Exit codes:\n"
                << L"  0  fully completed (everything wiped/verified)\n"
                << L"  1  partial: skips, unsupported or failed items remain\n"
                << L"  2  invalid command line\n";

            return 2;
        }

        if (mode == L"--verify")
            opts.mode = Mode::Verify;
        else if (mode == L"--wipe")
            opts.mode = Mode::Wipe;
        else
            opts.mode = Mode::WipeSlack;

        if (opts.mode == Mode::Verify && opts.noVerify) {
            std::wcerr
                << L"--no-verify cannot be combined with --verify.\n";
            return 2;
        }

        // Probe the final path component without following reparse
        // points. For directories the security check and the walk must
        // share one handle chain: keep the probe FileId and re-open the
        // walk handle under that pin, holding the walk handle open from
        // the reparse check until the traversal finishes.
        DWORD pathAttrs = 0;
        uint64_t rootFileId = 0;

        {
            HANDLE probe = CreateFileW(
                path.c_str(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT |
                    FILE_FLAG_BACKUP_SEMANTICS,
                nullptr
            );

            if (probe == INVALID_HANDLE_VALUE)
                ThrowWin32(L"CreateFile(root path)");

            Handle rootHandle(probe);

            BY_HANDLE_FILE_INFORMATION rootInfo{};

            if (!GetFileInformationByHandle(
                    rootHandle.get(),
                    &rootInfo))
            {
                ThrowWin32(L"GetFileInformationByHandle(root path)");
            }

            pathAttrs = rootInfo.dwFileAttributes;
            rootFileId =
                (static_cast<uint64_t>(rootInfo.nFileIndexHigh)
                 << 32) |
                static_cast<uint64_t>(rootInfo.nFileIndexLow);
        }

        const bool targetIsDir =
            (pathAttrs & FILE_ATTRIBUTE_DIRECTORY) != 0;

        if (targetIsDir && !opts.recursive) {
            Fail(
                "Directories are not supported without -r/--recursive."
            );
        }

        // Reject reparse roots independent of targetIsDir: a directory
        // junction/symlink must not be traversed as the wipe root.
        if (pathAttrs & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            Fail(
                "Reparse points/symlinks are intentionally rejected."
            );
        }

        // ----------------------------------------------------
        // Recursive directory run
        // ----------------------------------------------------

        if (targetIsDir) {
            path = ToExtendedPath(path);

            // Open the walk handle now and pin it to the probe's FileId
            // before any traversal; this handle stays open until the
            // walk (including root disposition) completes.
            DWORD rootOpenErr = ERROR_SUCCESS;
            bool rootHasDelete = false;
            Handle walkRoot(
                OpenDirectoryForWalk(path, rootOpenErr, &rootHasDelete)
            );

            if (!walkRoot.valid()) {
                ThrowWin32(
                    L"CreateFile(directory walk root)",
                    rootOpenErr
                );
            }

            {
                BY_HANDLE_FILE_INFORMATION walkInfo{};

                if (!GetFileInformationByHandle(
                        walkRoot.get(),
                        &walkInfo))
                {
                    ThrowWin32(
                        L"GetFileInformationByHandle(directory walk root)"
                    );
                }

                if (walkInfo.dwFileAttributes &
                    FILE_ATTRIBUTE_REPARSE_POINT)
                {
                    Fail(
                        "Reparse points/symlinks are intentionally rejected."
                    );
                }

                uint64_t walkId =
                    (static_cast<uint64_t>(walkInfo.nFileIndexHigh)
                     << 32) |
                    static_cast<uint64_t>(walkInfo.nFileIndexLow);

                if (rootFileId && walkId != rootFileId) {
                    Fail(
                        "root identity changed "
                        "(FileId mismatch after walk-root open)"
                    );
                }
            }

            if (opts.dryRun) {
                std::vector<FileResult> results;
                uint64_t dirsRemoved = 0;
                VolumeContext vc;

                // Same NTFS fail-fast as a real run (no raw volume open).
                std::string volError;

                if (!EnsureVolume(path, opts, vc, volError))
                    Fail(volError);

                WalkDirectoryHandle(
                    path,
                    walkRoot,
                    rootHasDelete,
                    opts,
                    vc,
                    results,
                    dirsRemoved
                );

                PrintSummary(results, dirsRemoved, opts);

                return ExitCodeFromResults(results);
            }

            if (!opts.yes) {
                TreeStats st{};
                CountTree(path, st);

                if (!ConfirmRecursive(st, opts)) {
                    std::wcout << L"Aborted.\n";
                    return 1;
                }
            }

            VolumeContext vc;
            std::string volError;

            // Fail fast on non-NTFS / missing Administrator rights.
            if (!EnsureVolume(path, opts, vc, volError))
                Fail(volError);

            std::vector<FileResult> results;
            uint64_t dirsRemoved = 0;

            WalkDirectoryHandle(
                path,
                walkRoot,
                rootHasDelete,
                opts,
                vc,
                results,
                dirsRemoved
            );

            PrintSummary(results, dirsRemoved, opts);

            return ExitCodeFromResults(results);
        }

        // ----------------------------------------------------
        // Single file — pin the wipe handle to the probe FileId
        // ----------------------------------------------------

        if (opts.dryRun) {
            FileResult r = DryRunFile(path, opts, rootFileId);
            PrintResult(r);

            if (r.status == FileStatus::Failed ||
                r.status == FileStatus::Skipped ||
                r.status == FileStatus::Unsupported)
            {
                return 1;
            }

            std::wcout << L"Dry run - no changes were made.\n";
            return 0;
        }

        VolumeContext vc;

        FileResult result =
            ProcessOneFile(path, opts, vc, rootFileId);

        if (result.status == FileStatus::Wiped ||
            result.status == FileStatus::Verified ||
            result.status == FileStatus::Empty)
        {
            return 0;
        }

        // Skipped/Unsupported/Failed: content may remain.
        if (result.status == FileStatus::Skipped ||
            result.status == FileStatus::Unsupported ||
            result.status == FileStatus::Failed)
        {
            if (!result.message.empty())
                std::cerr << "\nERROR: " << result.message << "\n";

            return 1;
        }

        Fail(result.message);
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr
            << "\nERROR: "
            << e.what()
            << "\n";

        return 1;
    }
}
