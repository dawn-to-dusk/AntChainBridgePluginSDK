#include <eosio/eosio.hpp>
#include <eosio/print.hpp>
// #include <ly.data/ly.data.hpp>
#include "../include/ly.data/ly.data.hpp"

using namespace eosio;

ACTION lydata::setdata(name sender, name data_name, uint64_t data_value){
    require_auth(sender);

    set_data_internal(sender, data_name, data_value);
}

ACTION lydata::printdata(){
    print("print data");
}

void lydata::set_data_internal(name sender, name data_name, uint64_t data_value) {
    auto data_itr = tbl_datas.find(data_name.value);

    if( data_itr == tbl_datas.end() ) {
        tbl_datas.emplace(sender, [&]( auto& row ) {
            row.data_name = data_name;
            row.data_value = data_value;
            print("add data");
        });
    } else {
        tbl_datas.modify(data_itr, sender, [&]( auto& row ) {
            row.data_name = data_name;
            row.data_value = data_value;
            print("modify data");
        });
    }
}