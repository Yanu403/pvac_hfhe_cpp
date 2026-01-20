#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>

using namespace pvac;

namespace fs = std::filesystem;

namespace Magic {
    constexpr uint32_t CT = 0x66699666;
    constexpr uint32_t SK = 0x66666999;
    constexpr uint32_t PK = 0x06660666;
    constexpr uint32_t VER = 1;
}

// ==================================================================
// SERIALIZATION FUNCTIONS (io & ser) - FULL COPY DARI ASLI
// ==================================================================

namespace io {
    auto put32 = [](std::ostream& o, uint32_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 4);
    };

    auto put64 = [](std::ostream& o, uint64_t x) -> std::ostream& {
        return o.write(reinterpret_cast<const char*>(&x), 8);
    };

    auto get32 = [](std::istream& i) -> uint32_t {
        uint32_t x = 0; i.read(reinterpret_cast<char*>(&x), 4); return x;
    };

    auto get64 = [](std::istream& i) -> uint64_t {
        uint64_t x = 0; i.read(reinterpret_cast<char*>(&x), 8); return x;
    };

    auto putBv = [](std::ostream& o, const BitVec& b) -> std::ostream& {
        put32(o, (uint32_t)b.nbits);
        for (size_t i = 0; i < (b.nbits + 63) / 64; ++i) put64(o, b.w[i]);
        return o;
    };

    auto getBv = [](std::istream& i) -> BitVec {
        auto b = BitVec::make((int)get32(i));
        for (size_t j = 0; j < (b.nbits + 63) / 64; ++j) b.w[j] = get64(i);
        return b;
    };

    auto putFp = [](std::ostream& o, const Fp& f) -> std::ostream& {
        put64(o, f.lo); return put64(o, f.hi);
    };

    auto getFp = [](std::istream& i) -> Fp {
        return {get64(i), get64(i)};
    };
}

namespace ser {
    using namespace io;

    auto putLayer = [](std::ostream& o, const Layer& L) {
        o.put((uint8_t)L.rule);
        if (L.rule == RRule::BASE) {
            put64(o, L.seed.ztag);
            put64(o, L.seed.nonce.lo);
            put64(o, L.seed.nonce.hi);
        } else if (L.rule == RRule::PROD) {
            put32(o, L.pa);
            put32(o, L.pb);
        } else {
            put64(o, 0); put64(o, 0); put64(o, 0);
        }
    };

    auto getLayer = [](std::istream& i) -> Layer {
        Layer L{};
        L.rule = (RRule)i.get();
        if (L.rule == RRule::BASE) {
            L.seed.ztag = get64(i);
            L.seed.nonce.lo = get64(i);
            L.seed.nonce.hi = get64(i);
        } else if (L.rule == RRule::PROD) {
            L.pa = get32(i);
            L.pb = get32(i);
        } else {
            (void)get64(i); (void)get64(i); (void)get64(i);
        }
        return L;
    };

    auto putEdge = [](std::ostream& o, const Edge& e) {
        put32(o, e.layer_id);
        o.write(reinterpret_cast<const char*>(&e.idx), 2);
        o.put(e.ch);
        o.put(0);
        putFp(o, e.w);
        putBv(o, e.s);
    };

    auto getEdge = [](std::istream& i) -> Edge {
        Edge e{};
        e.layer_id = get32(i);
        i.read(reinterpret_cast<char*>(&e.idx), 2);
        e.ch = (uint8_t)i.get();
        i.get();
        e.w = getFp(i);
        e.s = getBv(i);
        return e;
    };

    auto putCipher = [](std::ostream& o, const Cipher& C) {
        put32(o, (uint32_t)C.L.size());
        put32(o, (uint32_t)C.E.size());
        for (const auto& L : C.L) putLayer(o, L);
        for (const auto& e : C.E) putEdge(o, e);
    };

    auto getCipher = [](std::istream& i) -> Cipher {
        Cipher C;
        auto nL = get32(i), nE = get32(i);
        C.L.resize(nL); C.E.resize(nE);
        for (auto& L : C.L) L = getLayer(i);
        for (auto& e : C.E) e = getEdge(i);
        return C;
    };
}

// ==================================================================
// LOAD / SAVE FUNCTIONS
// ==================================================================

auto loadCts = [](const std::string& path) -> std::vector<Cipher> {
    std::ifstream i(path, std::ios::binary);
    if (!i || io::get32(i) != Magic::CT || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad CT: " + path);

    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
};

auto saveCts = [](const std::vector<Cipher>& cts, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::CT);
    io::put32(o, Magic::VER);
    io::put64(o, cts.size());
    for (const auto& c : cts) ser::putCipher(o, c);
};

auto savePk = [](const PubKey& p, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::PK);
    io::put32(o, Magic::VER);
    io::put32(o, p.prm.m_bits);
    io::put32(o, p.prm.B);
    io::put32(o, p.prm.lpn_t);
    io::put32(o, p.prm.lpn_n);
    io::put32(o, p.prm.lpn_tau_num);
    io::put32(o, p.prm.lpn_tau_den);
    io::put32(o, p.prm.noise_entropy_bits);
    io::put32(o, p.prm.depth_slope_bits);
    uint64_t t2;
    std::memcpy(&t2, &p.prm.tuple2_fraction, 8);
    io::put64(o, t2);
    io::put32(o, p.prm.edge_budget);
    io::put64(o, p.canon_tag);
    o.write(reinterpret_cast<const char*>(p.H_digest.data()), 32);
    io::put64(o, p.H.size());
    for (const auto& h : p.H) io::putBv(o, h);
    io::put64(o, p.ubk.perm.size());
    for (auto v : p.ubk.perm) io::put32(o, v);
    io::put64(o, p.ubk.inv.size());
    for (auto v : p.ubk.inv) io::put32(o, v);
    io::putFp(o, p.omega_B);
    io::put64(o, p.powg_B.size());
    for (const auto& f : p.powg_B) io::putFp(o, f);
};

auto saveSk = [](const SecKey& s, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::SK);
    io::put32(o, Magic::VER);
    for (int j = 0; j < 4; ++j) io::put64(o, s.prf_k[j]);
    io::put64(o, s.lpn_s_bits.size());
    for (auto w : s.lpn_s_bits) io::put64(o, w);
};

auto saveParams = [](const Params& p, const std::string& path) {
    std::ofstream(path) << "{\n"
        << "  \"m_bits\": " << p.m_bits << ",\n"
        << "  \"B\": " << p.B << ",\n"
        << "  \"lpn_t\": " << p.lpn_t << ",\n"
        << "  \"lpn_n\": " << p.lpn_n << ",\n"
        << "  \"lpn_tau_num\": " << p.lpn_tau_num << ",\n"
        << "  \"lpn_tau_den\": " << p.lpn_tau_den << ",\n"
        << "  \"noise_entropy_bits\": " << p.noise_entropy_bits << ",\n"
        << "  \"depth_slope_bits\": " << p.depth_slope_bits << ",\n"
        << "  \"tuple2_fraction\": " << p.tuple2_fraction << ",\n"
        << "  \"edge_budget\": " << p.edge_budget << "\n"
        << "}\n";
};

int main() {
    std::cout << "- bounty3 gen - TEST LOKAL DENGAN DATA KNOWN\n";

    // DATA KNOWN UNTUK TES SANDBOX (ganti sesuai keinginan)
    const std::string mnemonic = "test wallet phrase one two three four five six seven eight nine";
    const uint64_t number = 12345;
    std::string data = "mnemonic: " + mnemonic + ", number: " + std::to_string(number);

    std::cout << "Data yang akan dienkripsi: " << data << "\n";
    std::cout << "Panjang data: " << data.size() << " bytes\n\n";

    Params prm;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);

    auto ct = enc_text(pk, sk, data);

    fs::create_directories("bounty3_data");
    saveCts({ct}, "bounty3_data/seed.ct");
    savePk(pk, "bounty3_data/pk.bin");
    saveSk(sk, "bounty3_data/sk.bin");
    saveParams(prm, "bounty3_data/params.json");

    std::cout << "Generated bounty3_data/seed.ct, pk.bin, sk.bin, params.json\n";

    // VERIFIKASI DECODE DENGAN SK (untuk konfirmasi benar)
    auto decoded = dec_text(pk, sk, ct);
    std::cout << "Decoded dengan sk (harus match data known): " << decoded << "\n";

    if (decoded == data) {
        std::cout << "Verifikasi berhasil! Data recover sama dengan known.\n";
    } else {
        std::cout << "Verifikasi gagal! Decoded != known data.\n";
    }

    std::cout << "ok\n";
    return 0;
}
