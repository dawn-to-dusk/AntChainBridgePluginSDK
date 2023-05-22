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

import cn.hutool.core.collection.ListUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSONObject;
import com.alipay.antchain.bridge.commons.bbc.AbstractBBCContext;
import com.alipay.antchain.bridge.commons.bbc.syscontract.AuthMessageContract;
import com.alipay.antchain.bridge.commons.bbc.syscontract.ContractStatusEnum;
import com.alipay.antchain.bridge.commons.bbc.syscontract.SDPContract;
import com.alipay.antchain.bridge.commons.core.base.CrossChainMessage;
import com.alipay.antchain.bridge.commons.core.base.CrossChainMessageReceipt;
import com.alipay.antchain.bridge.plugins.lib.BBCService;
import com.alipay.antchain.bridge.plugins.spi.bbc.IBBCService;
import jdk.nashorn.internal.parser.JSONParser;
import lombok.Getter;
import okhttp3.RequestBody;
import one.block.eosiojava.error.rpcProvider.RpcProviderError;
import one.block.eosiojava.error.serializationProvider.SerializationProviderError;
import one.block.eosiojava.implementations.ABIProviderImpl;
import one.block.eosiojava.interfaces.IRPCProvider;
import one.block.eosiojava.interfaces.ISerializationProvider;
import one.block.eosiojavaabieosserializationprovider.AbiEosSerializationProviderImpl;
import one.block.eosiojavarpcprovider.error.EosioJavaRpcProviderInitializerError;
import one.block.eosiojavarpcprovider.implementations.EosioJavaRpcProviderImpl;
import one.block.eosiosoftkeysignatureprovider.SoftKeySignatureProviderImpl;
import one.block.eosiosoftkeysignatureprovider.error.ImportKeyError;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


@BBCService(products = "eos", pluginId = "plugin-eos")
@Getter
public class EosBBCService implements IBBCService {

    private EosConfig config;
    
    private AbstractBBCContext bbcContext;

    private EosioJavaRpcProviderImpl rpcProvider;

    private ISerializationProvider serializationProvider;

    private ABIProviderImpl abiProvider;

    private SoftKeySignatureProviderImpl signatureProvider;
    
    @Override
    public void startup(AbstractBBCContext abstractBBCContext) {
        System.out.printf("EOS BBCService startup with context: %s \n",
                new String(abstractBBCContext.getConfForBlockchainClient()));

        if (ObjectUtil.isNull(abstractBBCContext)) {
            throw new RuntimeException("null bbc context");
        }
        if (ObjectUtil.isEmpty(abstractBBCContext.getConfForBlockchainClient())) {
            throw new RuntimeException("empty blockchain client conf");
        }

        // 1. Obtain the configuration information
        try {
            config = EosConfig.fromJsonString(new String(abstractBBCContext.getConfForBlockchainClient()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(StrUtil.isEmpty(config.getPrivateKey())){
            throw new RuntimeException("private key is empty");
        }

        if(StrUtil.isEmpty(config.getUrl())){
            throw new RuntimeException("eos url is empty");
        }

        // 2. Connect to the Eos network
        try {
            rpcProvider = new EosioJavaRpcProviderImpl(config.getUrl());
            serializationProvider = new AbiEosSerializationProviderImpl();
            abiProvider = new ABIProviderImpl(rpcProvider, serializationProvider);

            signatureProvider = new SoftKeySignatureProviderImpl();
            signatureProvider.importKey(config.getPrivateKey());
        } catch (EosioJavaRpcProviderInitializerError | SerializationProviderError | ImportKeyError e) {
            throw new RuntimeException(String.format("failed to connect eos (url: %s)", config.getUrl()), e);
        }

        // 3. set context
        this.bbcContext = abstractBBCContext;

        // 4. check the pre-deployed contracts into context
        if (ObjectUtil.isNull(abstractBBCContext.getAuthMessageContract())){
            if (StrUtil.isEmpty(this.config.getAmContractAddressDeployed())) {
                throw new RuntimeException(String.format("The am contract is not deployed"));
            } else {
                AuthMessageContract authMessageContract = new AuthMessageContract();
                authMessageContract.setContractAddress(this.config.getAmContractAddressDeployed());
                authMessageContract.setStatus(ContractStatusEnum.CONTRACT_DEPLOYED);
                this.bbcContext.setAuthMessageContract(authMessageContract);
            }
        }

        if (ObjectUtil.isNull(abstractBBCContext.getSdpContract())) {
            if (StrUtil.isEmpty(this.config.getSdpContractAddressDeployed())) {
                throw new RuntimeException(String.format("The sdp contract is not deployed"));
            } else {
                SDPContract sdpContract = new SDPContract();
                sdpContract.setContractAddress(this.config.getSdpContractAddressDeployed());
                sdpContract.setStatus(ContractStatusEnum.CONTRACT_DEPLOYED);
                this.bbcContext.setSdpContract(sdpContract);
            }
        }
    }

    @Override
    public void shutdown() {
        System.out.println("shut down EOS BBCService!");
    }

    @Override
    public AbstractBBCContext getContext() {
        if (ObjectUtil.isNull(this.bbcContext)){
            throw new RuntimeException("empty bbc context");
        }

        System.out.printf("EOS BBCService context (amAddr: %s, amStatus: %s, sdpAddr: %s, sdpStatus: %s) \n",
                this.bbcContext.getAuthMessageContract() != null ? this.bbcContext.getAuthMessageContract().getContractAddress() : "",
                this.bbcContext.getAuthMessageContract() != null ? this.bbcContext.getAuthMessageContract().getStatus() : "",
                this.bbcContext.getSdpContract() != null ? this.bbcContext.getSdpContract().getContractAddress() : "",
                this.bbcContext.getSdpContract() != null ? this.bbcContext.getSdpContract().getStatus() : ""
        );

        return this.bbcContext;
    }

    @Override
    public CrossChainMessageReceipt readCrossChainMessageReceipt(String txHash) {
        CrossChainMessageReceipt crossChainMessageReceipt = new CrossChainMessageReceipt();

        // 1. Obtain Eos receipt according to transaction hash
        String getTransactionRequest = "{\n" +
                "\t\"id\": \"transaction id\",\n" +
                "}";

        RequestBody requestBody = RequestBody.create(okhttp3.MediaType.parse("application/json; charset=utf-8"),
                getTransactionRequest);
        String response = null;

        try {
            response = rpcProvider.getTransaction(requestBody);
        } catch (RpcProviderError e) {
            throw new RuntimeException(e);
        }

//        JSONParser parser = new JSONParser();
//        JSONObject jsonObject = (JSONObject)parser.parse(response);
//        String transactionId = (String) jsonObject.get("id");
//        Long blockNum = (Long) jsonObject.get("block_num");
        // todo

        System.out.printf("cross chain message receipt: %s\n", crossChainMessageReceipt);
        return crossChainMessageReceipt;
    }

    @Override
    public List<CrossChainMessage> readCrossChainMessagesByHeight(long height) {
        if (ObjectUtil.isNull(this.bbcContext)){
            throw new RuntimeException("empty bbc context");
        }

        if (ObjectUtil.isNull(this.bbcContext.getAuthMessageContract())){
            throw new RuntimeException("empty am contract in bbc context");
        }

        try {
            List<CrossChainMessage> messageList = ListUtil.toList();
            // todo

            System.out.printf("read cross chain messages (height: %d, msgs: %s)\n",
                    height,
                    messageList.stream().map(Object::toString).collect(Collectors.joining(","))
            );

            return messageList;
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to readCrossChainMessagesByHeight (Height: %d, contractAddr: %s, topic: %s)",
                            height,
                            this.bbcContext.getAuthMessageContract().getContractAddress(),
                            "topicString" // todo
                    ), e
            );
        }
    }

    @Override
    public Long queryLatestHeight() {
        Long l = 0L;
        try {
            // todo
        } catch (Exception e) {
            throw new RuntimeException("failed to query latest height", e);
        }

        System.out.printf("latest height: %d\n", l);
        return l;
    }

    @Override
    public void setupAuthMessageContract() {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)){
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNotNull(this.bbcContext.getAuthMessageContract())
                && StrUtil.isNotEmpty(this.bbcContext.getAuthMessageContract().getContractAddress())) {
            // If the contract has been pre-deployed and the contract address is configured in the configuration file,
            // there is no need to redeploy.
        } else {
            throw new RuntimeException("Please contact EOS Chain operations personnel to pre-deploy AM contract " +
                    "and add the contract information to the plugin configuration file");
        }
    }

    @Override
    public void setupSDPMessageContract() {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)){
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNotNull(this.bbcContext.getSdpContract())
                && StrUtil.isNotEmpty(this.bbcContext.getSdpContract().getContractAddress())) {
            // If the contract has been pre-deployed and the contract address is configured in the configuration file,
            // there is no need to redeploy.
        } else {
            throw new RuntimeException("Please contact EOS Chain operations personnel to pre-deploy SDP contract " +
                    "and add the contract information to the plugin configuration file");
        }
    }

    @Override
    public long querySDPMessageSeq(String senderDomain, String senderID, String receiverDomain, String receiverID) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)){
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getSdpContract())){
            throw new RuntimeException("empty sdp contract in bbc context");
        }

        // 2. invoke sdpMsg
        long seq = 0;
        // todo

        return seq;
    }

    @Override
    public void setProtocol(String protocolAddress, String protocolType) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getAuthMessageContract())){
            throw new RuntimeException("empty am contract in bbc context");
        }

        // 2. invoke am contract
        // todo

        // 4. update am contract status
        try {
            // todo 检查是否调用成功
            this.bbcContext.getAuthMessageContract().setStatus(ContractStatusEnum.CONTRACT_READY);
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to update am contract status (address: %s)",
                            this.bbcContext.getAuthMessageContract().getContractAddress()
                    ), e);
        }
    }

    @Override
    public void setAmContract(String contractAddress) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getSdpContract())){
            throw new RuntimeException("empty sdp contract in bbc context");
        }

        // 2. invoke sdp contract
        // todo

        // 4. update sdp contract status
        try {
            // todo 检查所有信息是否都设置成功
            this.bbcContext.getSdpContract().setStatus(ContractStatusEnum.CONTRACT_READY);
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to update sdp contract status (address: %s)",
                            this.bbcContext.getSdpContract().getContractAddress()
                    ), e);
        }
    }

    @Override
    public void setLocalDomain(String domain) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (StrUtil.isEmpty(this.bbcContext.getSdpContract().getContractAddress())) {
            throw new RuntimeException("none sdp contract address");
        }

        // 2. invoke sdp contract
        // todo

        // 4. update sdp contract status
        try {
            // todo 检查所有信息是否都设置成功
            this.bbcContext.getSdpContract().setStatus(ContractStatusEnum.CONTRACT_READY);
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to update sdp contract status (address: %s)",
                            this.bbcContext.getSdpContract().getContractAddress()
                    ), e);
        }
    }

    // 将消息转发到接收链
    @Override
    public CrossChainMessageReceipt relayAuthMessage(byte[] rawMessage) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getAuthMessageContract())){
            throw new RuntimeException("empty am contract in bbc context");
        }

        System.out.printf("relay AM %s to %s \n",
                HexUtil.encodeHexStr(rawMessage), this.bbcContext.getAuthMessageContract().getContractAddress());

        // 2. creat Transaction
        try {
            CrossChainMessageReceipt crossChainMessageReceipt = new CrossChainMessageReceipt();

            // todo

            return crossChainMessageReceipt;
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format("failed to relay AM %s to %s",
                            HexUtil.encodeHexStr(rawMessage), this.bbcContext.getAuthMessageContract().getContractAddress()
                    ), e
            );
        }
    }
}
