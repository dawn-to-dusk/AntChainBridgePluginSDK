#include <eosio/eosio.hpp>
#include <eosio/print.hpp>
#include "../include/sys.am/sys.am.hpp"
#include "../include/sys.sdp/sys.sdp.hpp"
#include "../include/utils/bytes_to_type.hpp"
#include "../include/utils/type_to_bytes.hpp"
#include "../include/utils/utils.hpp"
#include "../include/utils/am_lib.hpp"

using namespace eosio;
using namespace std;
using namespace crosschain;

// todo : 验证是否需要
// todo : 将部署账户添加到releayer中？
ACTION sysam::init(const name& initializer){
    print("AMMSG_INFO: init am 1");
    print(initializer);
    print("AMMSG_INFO: init am 2");
}

ACTION sysam::addrelayer(const name& invoker, const name& relayer_account){
    require_auth(invoker);
    print("AMMSG_INFO: add relayer", relayer_account);

    auto data_itr = tbl_relayers.find(relayer_account.value);
    check(data_itr == tbl_relayers.end(), "AMMSG_INFO: the relayer account has been added");

    tbl_relayers.emplace(invoker, [&]( auto& row ) {
        row.relayer = relayer_account;
    });
}

ACTION sysam::setprotocol(const name& invoker, const name& protocol_account, const uint32_t& protocol_type){
    require_auth(invoker);
    print("AMMSG_INFO: set protocol, accout = ", protocol_account, "type = ", protocol_type);

    auto acc_itr = tbl_protocols_by_account.find(protocol_account.value);
    check(acc_itr == tbl_protocols_by_account.end(), "AMMSG_INFO: the protocol account has been setted");

    auto typ_itr = tbl_protocols_by_type.find(protocol_type);
    check(typ_itr == tbl_protocols_by_type.end(), "AMMSG_INFO: the protocol type has been setted");
    
    tbl_protocols_by_account.emplace(invoker, [&]( auto& row ) {
        row.protocol_account = protocol_account;
        row.protocol_type = protocol_type;
    });

    tbl_protocols_by_type.emplace(invoker, [&]( auto& row ) {
        row.protocol_account = protocol_account;
        row.protocol_type = protocol_type;
    });
}

ACTION sysam::test2()
{
    print("AMMSG_INFO: ==============test 2\n");
}

// recv from protocol
ACTION sysam::recvprotocol(const name& invoker, const name& sender_account, const string& msg){
    print("AMMSG_INFO: recvprotocol start\n");
    require_auth(invoker);
    only_protocols(invoker);
    print_f("AMMSG_INFO: recv msg[%] from protocol % \n", msg, invoker);

    uint32_t protocol_type = get_protocol_type_by_contract(invoker);
    uint32_t msg_size = BytesReserveForString(msg.size()) + 4 + 32 + 4;
    string pkg(32 + BytesReserveForString(msg_size), 0); // like EVM logdata
    uint32_t offset = 32 + 32 + msg_size;
    uint32_t version = 1;
    print_f("AMMSG_INFO: get protocol_type: %, msg_size: %, pkg: %, offset and version\n", protocol_type, msg_size, pkg);

    Uint32ToBytes(version, pkg, offset);
    NameToBytes(sender_account, pkg, offset);
    Uint32ToBytes(protocol_type, pkg, offset);
    StringToBytes(msg, pkg, offset);
    
    // compatible
    Uint32ToBytes(msg_size, pkg, offset);
    offset -= 28;
    Uint32ToBytes(32, pkg, offset);
    offset -= 28;
      
    check(0 == offset, "AMMSG_INFO: offset incorrect RecvFromProtocol");

    // 跨合约调用自己 emit SendAuthMessage
    SEND_INLINE_ACTION(*this, crossing, {get_self(), "active"_n}, {get_self(), pkg})
}

ACTION sysam::crossing(const name& invoker, const string& msg){
    require_auth(invoker);

    check(invoker == get_self(), "only am contract");
    print_f("crosschain!!! invoker: %, msg:\n", invoker);
    printhex(msg.c_str(), msg.size()); 
}

// recv from relayer
ACTION sysam::recvrelayer(const name& invoker, const string& pkg){
    require_auth(invoker);
    only_relayers(invoker);
    print("AMMSG_INFO: recv pkh ", pkg ," from relayer ", invoker);

    uint32_t offset = 0;
    while(offset<pkg.size()) {
        string hints;
        string proof;
        SequentialBytesToString(pkg, offset, hints);
        SequentialBytesToString(pkg, offset, proof);
        print("AMMSG_INFO: after data transfder");

        // 中继解析proof获取domain及pkg
        string domain_name = "";
        string pkg = "";
        check(decode_proof(proof, domain_name, pkg), "AMMSG_ERROR: decode proof failed");
        print("AMMSG_INFO: after proof decode");
        
        // 转发am消息到上层协议 方法待检查
        // forward_am_pkg(invoker, domain_name, pkg);
        print("AMMSG_INFO: after forward am pkg");
    }
    check(pkg.size() == offset, "AMMSG_ERROR: offset incorrect RecvPkgFromRelayerCore");
}

bool sysam::decode_proof(const std::string& raw_proof, std::string& domain, std::string& pkg){
        Proof proof;
        uint32_t offset = 6;
        while (offset < raw_proof.length()) {
            TLVItem item;
            if(!ParseTLVItem(raw_proof, offset, item)) return false;

            switch(item.tag){
            case TLV_PROOF_REQUEST:
                if(!DecodeRequestFromBytes(item.value, proof.req)) return false;
                break;
            case TLV_PROOF_RESPONSE_BODY:
                proof.raw_resp_body = item.value;
                break;
            case TLV_PROOF_ERROR_CODE:
                if(!ReadUint32LittleEndian(item.value, 0, proof.error_code)){ return false; }
                break;
            case TLV_PROOF_ERROR_MSG:
                proof.error_msg = item.value;
                break;
            case TLV_PROOF_SENDER_DOMAIN:
                proof.sender_domain = item.value;
                break;
            case TLV_PROOF_VERSION:
                if(!ReadUint16LittleEndian(item.value, 0, proof.version)){ return false; }
                break;
            default:
                break;
            }
        }

        domain = proof.sender_domain;

        check(proof.raw_resp_body.length() > 12, "AMMSG_ERROR: illegal length of udag resp");
        uint32_t l = 0;
        check(ReadUint32LittleEndian(proof.raw_resp_body, 8, l), "AMMSG_ERROR: decode proof resp body failed");
        check(proof.raw_resp_body.length() >= 12 + l, "AMMSG_ERROR: illegal length of udag resp");

        pkg.replace(pkg.begin(), pkg.end(), proof.raw_resp_body.begin() + 12, proof.raw_resp_body.begin() + 12 + l);

        return true;
    }

void sysam::forward_am_pkg(const name& invoker, const string& sender_domain, const string& pkg) {
    name sender_id;
    uint32_t protocol_type;
    string msg;
    parse_am_pkg(pkg, sender_id, protocol_type, msg);
    
    name protocol_name = get_protocol_account_by_type(protocol_type);

    // 调用protocol(sdp)合约的 recvmsg
    syssdp::recvmsg_action recvmsg(protocol_name, {get_self(), "active"_n});
    recvmsg.send(
        get_self(),
        // invoker,
        sender_domain,
        sender_id,
        msg
    );
}


void sysam::parse_am_pkg(const string& pkg, name& sender_id, uint32_t& protocol_type, string& msg) {
      uint32_t offset = pkg.size();
      uint32_t version;
      BytesToUint32(pkg, offset, version);
      check(1 == version, "AMMSG_ERROR: non supported AM package version");
      BytesToName(pkg, offset, sender_id);
      BytesToUint32(pkg, offset, protocol_type);
      BytesToString(pkg, offset, msg);
      check(0 == offset, "AMMSG_ERROR: offset incorrect ParseAMPackage");
}

name sysam::get_protocol_account_by_type(uint32_t protocol_type){
    auto data_itr = tbl_protocols_by_type.find(protocol_type);
    check(data_itr != tbl_protocols_by_type.end(), 
        "AMMSG_ERROR: type of the protocol account does not exist");
    return data_itr->protocol_account;
}

uint32_t sysam::get_protocol_type_by_contract(const name& protocol_account){
    auto data_itr = tbl_protocols_by_account.find(protocol_account.value);

    check(data_itr != tbl_protocols_by_account.end(), 
        "AMMSG_ERROR: the protocol account does not exist");
    return data_itr->protocol_type;
}

void sysam::only_relayers(const name& invoker) {
    auto data_itr = tbl_relayers.find(invoker.value);
    check(data_itr != tbl_relayers.end(), "the invoker should be relayer");
}


void sysam::only_protocols(const name& invoker) {
    auto data_itr = tbl_protocols_by_account.find(invoker.value);
    check(data_itr != tbl_protocols_by_account.end(), "the invoker should be protocol");
}