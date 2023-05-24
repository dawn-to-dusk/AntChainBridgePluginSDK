/*
 * Copyright 2023 Ant Group
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alipay.antchain.bridge.plugins.eos;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.Getter;
import lombok.Setter;

import java.io.IOException;

/**
 * Eos's configuration information
 * - Url for Eos node rpc
 * - Private key
 */
@Getter
@Setter
public class EosConfig {

    /**
     * 从json字符串反序列化
     *
     * @param jsonString raw json
     */
    public static EosConfig fromJsonString(String jsonString) throws IOException {
        return JSON.parseObject(jsonString, EosConfig.class);
    }

    @JSONField
    private String url;

    // todo: delete
    @JSONField
    private String userName;     // 调用者账户名称

    @JSONField
    private String userPriKey;   // 调用者账户的私钥

    @JSONField
    private long gasLimit;

    @JSONField
    private long gasPrice;

    @JSONField
    private String helloContractAddressDeployed;   // 合约账户名称 helloa

    @JSONField
    private String getDataContractAddressDeployed;   // 合约账户名称 getDataa

    @JSONField
    private String amContractAddressDeployed;   // 合约账户名称 ama

    @JSONField
    private String sdpContractAddressDeployed;  // 合约账户名称 sdpa

    /**
     * json序列化为字符串
     */
    public String toJsonString() {
        return JSON.toJSONString(this);
    }
}
