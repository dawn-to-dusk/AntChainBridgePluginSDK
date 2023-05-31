#pragma once

#include <eosio/eosio.hpp>

using namespace eosio;

class [[eosio::contract("ly.data")]] lydata : public contract {
public:
   using contract::contract;

   ACTION setdata(name sender, name data_name, uint64_t data_value);
   ACTION printdata();

   TABLE s_datas
   {
      name data_name;
      uint64_t data_value;
      uint64_t primary_key() const { return data_name.value; }
   };
   
   typedef multi_index<name("datas"), s_datas> t_datas;

private:
   t_datas tbl_datas = t_datas(get_self(), get_self().value);

   void set_data_internal(name sender, name data_name, uint64_t data_value);
};
