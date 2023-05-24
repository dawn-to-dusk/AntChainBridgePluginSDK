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

import client.domain.common.transaction.PackedTransaction;
import client.domain.common.transaction.TransactionAction;
import cn.hutool.core.collection.ListUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
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
import one.block.eosiojava.error.session.TransactionPrepareError;
import one.block.eosiojava.error.session.TransactionSignAndBroadCastError;
import one.block.eosiojava.implementations.ABIProviderImpl;
import one.block.eosiojava.interfaces.IRPCProvider;
import one.block.eosiojava.interfaces.ISerializationProvider;
import one.block.eosiojava.models.rpcProvider.Action;
import one.block.eosiojava.models.rpcProvider.Authorization;
import one.block.eosiojava.models.rpcProvider.Transaction;
import one.block.eosiojava.models.rpcProvider.TransactionConfig;
import one.block.eosiojava.models.rpcProvider.request.GetBlockRequest;
import one.block.eosiojava.models.rpcProvider.request.PushTransactionRequest;
import one.block.eosiojava.models.rpcProvider.response.GetBlockResponse;
import one.block.eosiojava.models.rpcProvider.response.GetInfoResponse;
import one.block.eosiojava.models.rpcProvider.response.PushTransactionResponse;
import one.block.eosiojava.models.rpcProvider.response.SendTransactionResponse;
import one.block.eosiojava.models.signatureProvider.EosioTransactionSignatureRequest;
import one.block.eosiojava.session.TransactionProcessor;
import one.block.eosiojava.session.TransactionSession;
import one.block.eosiojavaabieosserializationprovider.AbiEosSerializationProviderImpl;
import one.block.eosiojavarpcprovider.error.EosioJavaRpcProviderInitializerError;
import one.block.eosiojavarpcprovider.implementations.EosioJavaRpcProviderImpl;
import one.block.eosiosoftkeysignatureprovider.SoftKeySignatureProviderImpl;
import one.block.eosiosoftkeysignatureprovider.error.ImportKeyError;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@BBCService(products = "eos", pluginId = "plugin-eos")
@Getter
public class EosBBCService implements IBBCService {

    // todo 跨链事件标识？
    private static final String CROSSCHAIN_ACTION = "setcode";

    // ============================== SDP合约信息常量 ==============================
    // sdp合约「有序消息seq表」：该表记录跨链四元组对应的有序消息的seq
    // - 表名
    private static final String SDP_MSG_SEQ_TABLE = "sdpmsgseq";
    // - 主键的key值格式：senderDomain-senderID-receiverDomain-receiverID
    private static final String SDP_MSG_SEQ_TABLE_KEY_FORMAT = "%s-%s-%s-%s";
    // - 主键的value名称
    private static final String SDP_MSG_SEQ_TABLE_VALUE_NAME = "sdp_msg_seq";

    // sdp合约「初始化信息表」：该表记录am合约账户和链的localdomain
    // - 表名
    private static final String SDP_INIT_INFO_TABLE = "sdpinitinfo";
    // - 主键的key值：am/localdomain
    private static final String SDP_INIT_INFO_TABLE_KEY_AM = "sdp_init_am";
    private static final String SDP_INIT_INFO_TABLE_KEY_LOCALDOMAIN = "sdp_init_localdomain";
    // - 主键的value名称
    private static final String SDP_INIT_INFO_TABLE_VALUE_NAME = "sdp_init_account";

    // sdp合约中设置am合约账户的action
    // - 名称
    private static final String SDP_SET_AM_CONTRACT_ACTION = "setamcontract";
    // - 参数格式
    private static final String SDP_SET_AM_CONTRACT_PARAMETER_FORMAT = "{\n" +
            "  \"am_contract_account\": \"%s\"\n" +
            "}";

    // sdp合约中设置链localdomain的action
    // - 名称
    private static final String SDP_SET_LOCALDOMAIN_ACTION = "setlocaldomain";
    // - 参数格式
    private static final String SDP_SET_LOCALDOMAIN_PARAMETER_FORMAT = "{\n" +
            "  \"local_domain\": \"%s\"\n" +
            "}";

    // ============================== AM合约信息常量 ==============================
    // am合约「初始化信息表」：记录中继账户列表信息和上层协议账户列表信息
    // - 表名
    private static final String AM_INIT_INFO_TABLE = "aminitinfo";
    // - 主键的key值：relayers / protocols
    private static final String AM_INIT_INFO_TABLE_KEY_RELAYERS = "relayers";
    private static final String AM_INIT_INFO_TABLE_KEY_PROTOCOLS = "protocols";
    // - value名称
    private static final String AM_INIT_INFO_TABLE_VALUE_NAME = "am_init_value";

    // am合约「上层协议合约信息表」：记录上层协议类型到协议合约账户的映射
    // - 表名
    private static final String AM_PROTOCOLS_TABLE = "protocols";
    // - 主键的key格式：protocol类型  e.g. 0 (sdp)
    private static final String AM_PROTOCOLS_TABLE_KEY_FORMAT = "%s";
    private static final String AM_PROTOCOLS_TABLE_KEY_SDP = "0";
    // - value名称
    private static final String AM_PROTOCOLS_TABLE_VALUE_NAME = "protocol_account";

    // todo: unuse (插件不提供addrelayer功能！！！)
    // todo: eos运维人员应当提前使用中继账号在eos链上部署am合约，或由运维人员手动调用`addrelayer`将中继账户添加到am合约中
    // am合约中添加中继账户的action
    // - 名称
    private static final String AM_ADD_RELAYER_ACTION = "addrelayer";
    // - 参数格式
    private static final String AM_ADD_RELAYER_PARAMETER_FORMAT = "{\n" +
            "  \"relayer_account\": \"%s\"\n" +
            "}";

    // am合约中设置上层协议合约账户的action
    // - 名称
    private static final String AM_SET_PROTOCOL_ACTION = "setprotocol";
    // - 参数格式
    private static final String AM_SET_PROTOCOL_PARAMETER_FORMAT = "{\n" +
            "  \"protocol_account\": \"%s\",\n" +
            "  \"protocol_type\": \"%s\"\n" + // 0 - sdp
            "}";

    // am合约中接收中继消息的action
    // - 名称
    private static final String AM_RECV_PKG_FROM_RELAYER_ACTION = "recvpkgfromrelayer";
    // - 参数格式
    private static final String AM_RECV_PKG_FROM_RELAYER_PARAMETER_FORMAT = "{\n" +
            "  \"raw_msg\": \"%s\"\n" +
            "}";

    // ============================== 插件基本变量 ==============================
    // todo: 一些从config读取的合约信息是否要改成从bbcContext中读取
    private EosConfig config;

    private AbstractBBCContext bbcContext;

    // ============================== EOS-SDK相关组件 ==============================

    // rpc服务组件
    private EosioJavaRpcProviderImpl rpcProvider;

    // 序列化管理组件
    private ISerializationProvider serializationProvider;

    // 合约abi处理组件
    private ABIProviderImpl abiProvider;

    // 签名管理组件
    private SoftKeySignatureProviderImpl signatureProvider;

    // 交易处理器
    private TransactionSession session;

    // 交易提交器
    // - pushTransaction 同步提交
    // - sendTransaction 异步提交
    private TransactionProcessor processor;

    /**
     * 启动插件
     * <pre>
     *     1. 插件连接eos
     *     2. 检查context中是否携带已部署合约信息（需要携带）
     * </pre>
     * @param abstractBBCContext
     */
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

        if(StrUtil.isEmpty(config.getUserPriKey())){
            throw new RuntimeException("private key is empty");
        }

        if(StrUtil.isEmpty(config.getUrl())){
            throw new RuntimeException("eos url is empty");
        }

        // 2. Connect to the Eos network
        try {
            // 2.1 Initialize the various service components
            rpcProvider = new EosioJavaRpcProviderImpl(config.getUrl());

            serializationProvider = new AbiEosSerializationProviderImpl();

            abiProvider = new ABIProviderImpl(rpcProvider, serializationProvider);

            signatureProvider = new SoftKeySignatureProviderImpl();
            signatureProvider.importKey(config.getUserPriKey());

            // 2.2 Initializes the transaction processing component
            session = new TransactionSession(
                    serializationProvider,
                    rpcProvider,
                    abiProvider,
                    signatureProvider);

            processor = session.getTransactionProcessor();

            // 2.3 Now the TransactionConfig can be altered, if desired
            TransactionConfig transactionConfig = processor.getTransactionConfig();

            // Use blocksBehind (default 3) the current head block to calculate TAPOS
            transactionConfig.setUseLastIrreversible(false);
            // Set the expiration time of transactions 600(default 300) seconds later than the timestamp
            // of the block used to calculate TAPOS
            transactionConfig.setExpiresSeconds(600);

            // Update the TransactionProcessor with the config changes
            processor.setTransactionConfig(transactionConfig);

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

    /**
     * 关闭插件（当前没有什么需要操作）
     */
    @Override
    public void shutdown() {
        System.out.println("shut down EOS BBCService!");
    }

    /**
     * 返回上下文
     * @return
     */
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

    /**
     * EOS不支持插件部署合约，这里直接根据`bbcContext`判断`AM`合约是否已经部署好
     */
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

    /**
     * EOS不支持插件部署合约，这里直接根据`bbcContext`判断`SDP`合约是否已经部署好
     */
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

    /**
     * 根据交易哈希获取跨链交易结果信息
     *
     * @param txHash
     * @return
     */
    @Override
    public CrossChainMessageReceipt readCrossChainMessageReceipt(String txHash) {
        CrossChainMessageReceipt crossChainMessageReceipt = new CrossChainMessageReceipt();

        // 1. Obtain Eos receipt according to transaction hash
        String getTransactionRequest = String.format("{\n" +
                "\t\"id\": \"%s\",\n" +
                "}", txHash);
        RequestBody requestBody = RequestBody.create(okhttp3.MediaType.parse("application/json; charset=utf-8"),
                getTransactionRequest);

        String response = null;
        try {
            response = rpcProvider.getTransaction(requestBody);
        } catch (RpcProviderError e) {
            throw new RuntimeException(
                    String.format(
                            "failed to read cross chain message receipt (txHash: %s)", txHash
                    ), e
            );
        }

        // 2. Construct cross-chain message receipt
        Object receipt = null;
        if(response != null){
            receipt = new JSONObject((Map) JSONObject.parseObject(response).get("trx")).get("receipt");
        }
        if (receipt != null){
            String status = (String) new JSONObject((Map) receipt).get("status");

            crossChainMessageReceipt.setSuccessful(StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), status)
                    || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), status));
            crossChainMessageReceipt.setConfirmed(StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), status));
            crossChainMessageReceipt.setTxhash(txHash);
            crossChainMessageReceipt.setErrorMsg(receipt.toString());
        } else {
            crossChainMessageReceipt.setSuccessful(false);
            crossChainMessageReceipt.setConfirmed(false);
            crossChainMessageReceipt.setTxhash(txHash);
            crossChainMessageReceipt.setErrorMsg(response);
        }

        System.out.printf("cross chain message receipt: %s\n", crossChainMessageReceipt.getErrorMsg());
        return crossChainMessageReceipt;
    }

    /**
     * 根据区块高度获取相应区块中所有的跨链信息
     * <pre>
     *     1. 根据区块高度获取指定区块
     *     2. 获取区块中所有交易
     *     3. 获取每个交易中的action
     *     4. 如果action中包含跨链信息则取出
     * </pre>
     * @param height
     * @return
     */
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

            // 1. get block
            GetBlockResponse getBlockResponse = rpcProvider.getBlock(new GetBlockRequest(String.valueOf(height)));
            List<Map> transactions = getBlockResponse.getTransactions();

            // 2. get crosschain msgs
            for (Map txMap : transactions){
                PackedTransaction packedTransaction = JSONObject.parseObject(
                        JSONObject.toJSONString(((Map) txMap.get("trx")).get("transaction")),
                        PackedTransaction.class);

                for(TransactionAction action : packedTransaction.getActions()){
                    // todo: 如果这个action包含跨链事件标识
                    if(StrUtil.equals(CROSSCHAIN_ACTION, action.getName())){
                        messageList.add(
                                CrossChainMessage.createCrossChainMessage(
                                        CrossChainMessage.CrossChainMessageType.AUTH_MSG,
                                        getBlockResponse.getBlockNum().longValue(),
                                        new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS")
                                                .parse(getBlockResponse.getTimestamp()).getTime(),
                                        getBlockResponse.getId().getBytes(),
                                        action.getData().getBytes(),
                                        // todo: put ledger data, for SPV or other attestations
                                        "this time we need no verify. it's ok to set it with empty bytes".getBytes(),
                                        // todo: put proof data
                                        "this time we need no proof data. it's ok to set it with empty bytes".getBytes()
                                )
                        );
                    }

                }
            }

            System.out.printf("read cross chain messages (height: %d, msgs: \n\t%s)\n",
                    height,
                    String.join("\n\t", messageList.stream().map(m->JSON.toJSONString(m)).collect(Collectors.toList()))
            );

            return messageList;
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to readCrossChainMessagesByHeight (Height: %d, contractAddr: %s, topic: %s)",
                            height,
                            this.bbcContext.getAuthMessageContract().getContractAddress(),
                            CROSSCHAIN_ACTION // todo: 跨链事件标识？
                    ), e
            );
        }
    }

    /**
     * 获取最新区块高度
     * @return
     */
    @Override
    public Long queryLatestHeight() {
        Long l = 0L;
        try {
            GetInfoResponse getInfoResponse = rpcProvider.getInfo();
            l = getInfoResponse.getHeadBlockNum().longValue();
        } catch (Exception e) {
            throw new RuntimeException("failed to query latest height", e);
        }

        System.out.printf("latest height: %d\n", l);
        return l;
    }

    /**
     * 获取SDP合约中有序消息的seq
     * <pre>
     *     1. 检查sdp合约已部署
     *     2. 从sdp合约的`SDP_MSG_SEQ_TABLE`表中读取seq
     *
     *     todo:补充单测
     * </pre>
     * @param senderDomain
     * @param senderID
     * @param receiverDomain
     * @param receiverID
     * @return
     */
    @Override
    public long querySDPMessageSeq(String senderDomain, String senderID, String receiverDomain, String receiverID) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)){
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getSdpContract())){
            throw new RuntimeException("empty sdp contract in bbc context");
        }

        // 2. 读合约数据
        long seq = (long)bbcGetValueFromTableByKeyOnRpc(
                config.getSdpContractAddressDeployed(),
                config.getSdpContractAddressDeployed(),
                SDP_MSG_SEQ_TABLE,
                String.format(
                        SDP_MSG_SEQ_TABLE_KEY_FORMAT,
                        senderDomain,
                        senderID,
                        receiverDomain,
                        receiverID),
                SDP_MSG_SEQ_TABLE_VALUE_NAME
        );

        return seq;
    }

    /**
     * 设置AM合约中上层协议地址
     * <pre>
     *     1. 检查am合约已部署
     *     2. 调用am合约的`setprotocol`action
     *     3. 检查交易是否执行成功
     *     4. 判断合约是否ready
     *
     *     todo:补充单测
     * </pre>
     * @param protocolAddress
     * @param protocolType
     */
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
        SendTransactionResponse sendTransactionResponse = bbcInvokeContractsOnRpc(
                new String[][]{
                        {
                                this.bbcContext.getAuthMessageContract().getContractAddress(),
                                AM_SET_PROTOCOL_ACTION,
                                String.format(AM_SET_PROTOCOL_PARAMETER_FORMAT, protocolAddress, protocolType)
                        },
                });
        String txId = sendTransactionResponse.getTransactionId();
        String txStatus = bbcGetStatusByTransactionHashOnRpc(txId);

        // 3. check transaction
        if (StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), txStatus)
                || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus)){
            System.out.printf(
                    "set protocol (address: %s, type: %s) to AM %s%n by tx %s \n",
                    protocolAddress,
                    protocolType,
                    this.bbcContext.getAuthMessageContract().getContractAddress(),
                    txId
            );
        } else {
            throw new RuntimeException(String.format("fail to invoke setprotocol by send transaction %s", txId));
        }

        // 4. check if am is ready
        try {
            if(isAmReady()){
                this.bbcContext.getAuthMessageContract().setStatus(ContractStatusEnum.CONTRACT_READY);
            }
        } catch (Exception e) {
            throw new RuntimeException(
                String.format(
                    "failed to update am contract status (address: %s)",
                    this.bbcContext.getAuthMessageContract().getContractAddress()
                ), e);
        }
    }

    /**
     * 判断am合约是否ready
     * <pre>
     *     1. 中继账户名称已初始化
     *     2. 指定类型的上层协议合约名称已初始化
     * </pre>
     * @return
     */
    private boolean isAmReady() {
        return ((String[]) bbcGetValueFromTableByKeyOnRpc(
                this.bbcContext.getAuthMessageContract().getContractAddress(),
                this.bbcContext.getAuthMessageContract().getContractAddress(),
                AM_INIT_INFO_TABLE,
                AM_INIT_INFO_TABLE_KEY_RELAYERS,
                AM_INIT_INFO_TABLE_VALUE_NAME)).length > 0
            && ((String[]) bbcGetValueFromTableByKeyOnRpc(
                this.bbcContext.getAuthMessageContract().getContractAddress(),
                this.bbcContext.getAuthMessageContract().getContractAddress(),
                AM_INIT_INFO_TABLE,
                AM_INIT_INFO_TABLE_KEY_PROTOCOLS,
                AM_INIT_INFO_TABLE_VALUE_NAME)).length > 0;
    }

    /**
     * 设置SDP合约中AM合约账户
     * <pre>
     *     1. 检查sdp合约已部署
     *     2. 调用sdp合约的`setamcontract`action
     *     3. 检查交易是否执行成功
     *     4. 判断合约是否ready
     *
     *     todo:补充单测
     * </pre>
     * @param contractAddress
     */
    @Override
    public void setAmContract(String contractAddress) {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getSdpContract())) {
            throw new RuntimeException("empty sdp contract in bbc context");
        }

        // 2. invoke sdp contract
        SendTransactionResponse sendTransactionResponse = bbcInvokeContractsOnRpc(
                new String[][]{
                        {
                                this.bbcContext.getSdpContract().getContractAddress(),
                                SDP_SET_AM_CONTRACT_ACTION,
                                String.format(SDP_SET_AM_CONTRACT_PARAMETER_FORMAT, contractAddress)
                        },
                });
        String txId = sendTransactionResponse.getTransactionId();
        String txStatus = bbcGetStatusByTransactionHashOnRpc(txId);

        // 3. check transaction
        if (StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), txStatus)
                || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus)) {
            System.out.printf(
                    "set AM contract (%s) to SDP (%s) by tx %s \n",
                    contractAddress,
                    this.bbcContext.getSdpContract().getContractAddress(),
                    txId
            );
        } else {
            throw new RuntimeException(String.format("fail to invoke setamcontract by send transaction %s", txId));
        }

        // 4. check if sdp is ready
        try {
            if (isSdpReady()) {
                this.bbcContext.getSdpContract().setStatus(ContractStatusEnum.CONTRACT_READY);
            }
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to update sdp contract status (address: %s)",
                            this.bbcContext.getSdpContract().getContractAddress()
                    ), e);
        }
    }

    /**
     * 设置SDP合约中本地域名
     * <pre>
     *     1. 检查sdp合约已部署
     *     2. 调用sdp合约的`setlocaldoamin`action
     *     3. 检查交易是否执行成功
     *     4. 判断合约是否ready
     *
     *     todo:补充单测
     * </pre>
     * @param domain
     */
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
        SendTransactionResponse sendTransactionResponse = bbcInvokeContractsOnRpc(
                new String[][]{
                        {
                                this.bbcContext.getSdpContract().getContractAddress(),
                                SDP_SET_LOCALDOMAIN_ACTION,
                                String.format(SDP_SET_LOCALDOMAIN_PARAMETER_FORMAT, domain)
                        },
                });
        String txId = sendTransactionResponse.getTransactionId();
        String txStatus = bbcGetStatusByTransactionHashOnRpc(txId);

        // 3. check transaction
        if (StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), txStatus)
                || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus)) {
            System.out.printf(
                    "set localdomain (%s) to SDP (%s) by tx %s \n",
                    domain,
                    this.bbcContext.getSdpContract().getContractAddress(),
                    txId
            );
        } else {
            throw new RuntimeException(String.format("fail to invoke setlocaldomain by send transaction %s", txId));
        }

        // 4. update sdp contract status
        try {
            if (isSdpReady()) {
                this.bbcContext.getSdpContract().setStatus(ContractStatusEnum.CONTRACT_READY);
            }
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format(
                            "failed to update sdp contract status (address: %s)",
                            this.bbcContext.getSdpContract().getContractAddress()
                    ), e);
        }
    }

    /**
     * 判断sdp合约是否ready
     * <pre>
     *     1. am信息已经初始化
     *     2. localdomain信息已经初始化
     * </pre>
     * @return
     */
    private boolean isSdpReady() {
        return StrUtil.isNotEmpty((String) bbcGetValueFromTableByKeyOnRpc(
                this.bbcContext.getSdpContract().getContractAddress(),
                this.bbcContext.getSdpContract().getContractAddress(),
                SDP_INIT_INFO_TABLE,
                SDP_INIT_INFO_TABLE_KEY_AM,
                SDP_INIT_INFO_TABLE_VALUE_NAME))
            && StrUtil.isNotEmpty((String) bbcGetValueFromTableByKeyOnRpc(
                this.bbcContext.getSdpContract().getContractAddress(),
                this.bbcContext.getSdpContract().getContractAddress(),
                SDP_INIT_INFO_TABLE,
                SDP_INIT_INFO_TABLE_KEY_LOCALDOMAIN,
                SDP_INIT_INFO_TABLE_VALUE_NAME));
    }

    /**
     * 调用AM合约方法将中继消息转发到接收链
     * @param rawMessage
     * @return
     */
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

        // 2. invoke am contract
        SendTransactionResponse sendTransactionResponse = bbcInvokeContractsOnRpc(
                new String[][]{
                        {
                                this.bbcContext.getAuthMessageContract().getContractAddress(),
                                AM_RECV_PKG_FROM_RELAYER_ACTION,
                                String.format(AM_RECV_PKG_FROM_RELAYER_PARAMETER_FORMAT, rawMessage.toString())
                        },
                });
        String txId = sendTransactionResponse.getTransactionId();
        String txStatus = bbcGetStatusByTransactionHashOnRpc(txId);

        // 3. check transaction
        CrossChainMessageReceipt crossChainMessageReceipt = new CrossChainMessageReceipt();

        crossChainMessageReceipt.setSuccessful(StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), txStatus)
                || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus));
        crossChainMessageReceipt.setConfirmed(StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus));
        crossChainMessageReceipt.setTxhash(txId);
        crossChainMessageReceipt.setErrorMsg(sendTransactionResponse.toString());

        System.out.printf(
                "relay auth message (%s) by tx %s \n",
                rawMessage.toString(),
                txId
        );

        return crossChainMessageReceipt;
    }

    // ============================== EOS合约工具方法及测试demo ==============================
    // ============================== EOS合约工具方法及测试demo ==============================
    // ============================== EOS合约工具方法及测试demo ==============================

    /**
     * 合约工具方法：发送异步交易调用合约方法，可以一次调用多个合约
     * @param invokeParams
     * @return
     */
    private SendTransactionResponse bbcInvokeContractsOnRpc(String[][] invokeParams) {
        List<Action> actionList = new ArrayList<>();

        for (String[] infos : invokeParams) {
            if(infos.length != 3){
                throw new RuntimeException(String.format(
                        "the parameters length shouled be 3 but %s", infos.length));
            }

            Action action = new Action(
                    // 合约账户名
                    infos[0].trim(),
                    // aciton名
                    infos[1].trim(),
                    // 调用者权限
                    Arrays.asList(new Authorization[]{
                            new Authorization(config.getUserName(), "active")
                    }),
                    // 合约参数
                    infos[2].trim()
            );
            actionList.add(action);
        }

        try {
            processor.prepare(actionList);
        } catch (TransactionPrepareError e) {
            throw new RuntimeException("failed to prepare invoke contract action", e);
        }

        try {
            return processor.signAndBroadcast();
        } catch (TransactionSignAndBroadCastError e) {
            throw new RuntimeException("failed to sign and broadcast invoke contract action", e);
        }
    }

    /**
     * 合约工具方法：根据交易哈希查询交易回执状态
     * @param txHash
     * @return
     */
    private String bbcGetStatusByTransactionHashOnRpc(String txHash){
        String getTransactionRequest = String.format("{\n" +
                "\t\"id\": \"%s\",\n" +
                "}", txHash);
        RequestBody requestBody = RequestBody.create(okhttp3.MediaType.parse("application/json; charset=utf-8"),
                getTransactionRequest);

        String response = null;
        try {
            response = rpcProvider.getTransaction(requestBody);
        } catch (RpcProviderError e) {
            throw new RuntimeException(
                    String.format(
                            "failed to invoke getTransaction rpc (req: %s)", getTransactionRequest
                    ), e
            );
        }

        Object receipt = null;
        if(response != null){
            receipt = new JSONObject((Map) JSONObject.parseObject(response).get("trx")).get("receipt");
        }

        if (receipt != null){
            return (String) new JSONObject((Map) receipt).get("status");
        } else {
            return EosTransactionStatusEnum.UNKNOW.getStatus();
        }
    }

    /**
     * 合约工具方法：读取合约存储表格数据
     * @param contractAcc
     * @param tableScope
     * @param tableName
     * @param tableKey
     * @param valueName
     * @return
     */
    private Object bbcGetValueFromTableByKeyOnRpc(
            String contractAcc, String tableScope, String tableName, String tableKey, String valueName){
        // 1. 构造rpc请求
        String getTableRowsRequest = String.format("{\n" +
                        // 合约账户
                        "\t\"code\": \"%s\",\n" +
                        // 表的范围，一般和合约账户相同
                        "\t\"scope\": \"%s\",\n" +
                        // 表名称
                        "\t\"table\": \"%s\",\n" +
                        // 表项主键值（rpc可选参数，当前方法中要求输入）
                        "\t\"table_key\": \"%s\",\n" +
                        // 结果用json编码
                        "\t\"json\": true\n" +

                        "}",
                contractAcc,
                tableScope,
                tableName,
                tableKey);
        RequestBody requestBody = RequestBody.create(okhttp3.MediaType.parse("application/json; charset=utf-8"),
                getTableRowsRequest);

        // 2. 发送rpc请求
        String response = null;
        try {
            response = rpcProvider.getTableRows(requestBody);
        } catch (RpcProviderError  | RuntimeException e) {
            throw new RuntimeException(
                    String.format(
                            "failed to invoke getTableRows rpc (req: %s)", getTableRowsRequest
                    ), e
            );
        }

        // 3. 解析rpc结果，返回结果应当只有0或1行的数据，根据value名称返回value值
        return JSON.parseObject(response)
                .getJSONArray("rows")
                .getJSONObject(0)
                .get(valueName);
    }

    /**
     * 测试demo: 合约调用
     * @return
     */
    public boolean demoInvokeHello() {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getAuthMessageContract())){
            throw new RuntimeException("empty am contract in bbc context");
        }

        // 2. invoke helloworld （异步）
        SendTransactionResponse sendTransactionResponse = bbcInvokeContractsOnRpc(
                new String[][]{
                        {
                                config.getHelloContractAddressDeployed(),
                                "hi",
                                "{}"
                        },
                });
        String txId = sendTransactionResponse.getTransactionId();
        String txStatus = bbcGetStatusByTransactionHashOnRpc(txId);
        if (StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), txStatus)
                || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus)){
            return true;
        } else {
            return false;
        }
    }

    /**
     * 测试demo: 数据读写
     * @return
     */
    public int demoInvokeSetData() {
        // 1. check context
        if (ObjectUtil.isNull(this.bbcContext)) {
            throw new RuntimeException("empty bbc context");
        }
        if (ObjectUtil.isNull(this.bbcContext.getAuthMessageContract())){
            throw new RuntimeException("empty am contract in bbc context");
        }

        // 2. invoke setdata 写数据
        SendTransactionResponse sendTransactionResponse = bbcInvokeContractsOnRpc(
                new String[][]{
                        {
                                config.getGetDataContractAddressDeployed(),
                                "setdata",
                                "{\n" +
                                        "  \"sender\": \""+ config.getUserName() +"\",\n" +
                                        "  \"data_name\": \"data1\",\n" +
                                        "  \"data_value\": \"10\"\n" +
                                        "}",
                        },
                });
        String txId = sendTransactionResponse.getTransactionId();
        String txStatus = bbcGetStatusByTransactionHashOnRpc(txId);
        if (StrUtil.equals(EosTransactionStatusEnum.EXECUTED.getStatus(), txStatus)
                || StrUtil.equals(EosTransactionStatusEnum.DELAYED.getStatus(), txStatus)){

        } else {
            throw new RuntimeException(String.format("fail to invoke set data by send transaction %s", txId));
        }

        // 3. 读数据
        int getInfoResponse = (int)bbcGetValueFromTableByKeyOnRpc(
                config.getGetDataContractAddressDeployed(),
                config.getGetDataContractAddressDeployed(),
                "datas",
                "data1",
                "data_value"
        );

        return getInfoResponse;
    }
}
