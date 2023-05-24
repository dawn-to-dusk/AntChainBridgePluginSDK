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
import com.alipay.antchain.bridge.commons.bbc.AbstractBBCContext;
import com.alipay.antchain.bridge.commons.bbc.DefaultBBCContext;
import com.alipay.antchain.bridge.commons.bbc.syscontract.AuthMessageContract;
import com.alipay.antchain.bridge.commons.bbc.syscontract.ContractStatusEnum;
import com.alipay.antchain.bridge.commons.bbc.syscontract.SDPContract;
import com.alipay.antchain.bridge.commons.core.base.CrossChainMessage;
import com.alipay.antchain.bridge.commons.core.base.CrossChainMessageReceipt;
import one.block.eosiojava.error.rpcProvider.GetBlockRpcError;
import one.block.eosiojava.models.rpcProvider.request.GetBlockRequest;
import one.block.eosiojava.models.rpcProvider.response.GetBlockResponse;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public class EosBBCServiceTest {

    private static final String VALID_URL = "http://127.0.0.1:8888";

    private static final String INVALID_URL = "127.0.0.1:9999";

    // !!! replace to your test key
    private static final String EOS_DEFAULT_PRIVATE_KEY = "5JvRDffBqoFFjiqXiVube1yDvNG35wxeNtwF4gsMJJqFEqPDkcG";
    //private static final String EOS_DEFAULT_PUBLIC_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV";

    private static final String EOS_SDP_CONTRACT_NAME = "eos.sdp";

    private static final String EOS_AM_CONTRACT_NAME = "eos.am";

    private static final String EOS_TX_HASH = "39376109501ac839cb45a47903b802e22113c957f03d805e0e6e05590aada11f";

    private static final String REMOTE_APP_CONTRACT = "0xdd11AA371492B94AB8CDEdf076F84ECCa72820e1";

    private static final long WAIT_TIME = 15000;

    private static EosBBCService eosBBCService;

    @Before
    public void init() throws Exception {
        eosBBCService = new EosBBCService();
    }

    /**
     * EOS的Startupb必须携带已部署合约信息
     */
    @Test
    public void testStartup(){
        // start up context success with deployed contract
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);
        Assert.assertNotNull(eosBBCService.getBbcContext().getAuthMessageContract());
        Assert.assertNotNull(eosBBCService.getBbcContext().getSdpContract());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, eosBBCService.getBbcContext().getAuthMessageContract().getStatus());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, eosBBCService.getBbcContext().getSdpContract().getStatus());

        // start up context success with ready contract
        AbstractBBCContext mockValidCtxWithPreReadyContracts = mockValidCtxWithPreReadyContracts();
        eosBBCService.startup(mockValidCtxWithPreReadyContracts);
        Assert.assertNotNull(eosBBCService.getBbcContext().getAuthMessageContract());
        Assert.assertNotNull(eosBBCService.getBbcContext().getSdpContract());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_READY, eosBBCService.getBbcContext().getAuthMessageContract().getStatus());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_READY, eosBBCService.getBbcContext().getSdpContract().getStatus());

        // start up failed without deployed contract
        AbstractBBCContext mockInvalidCtxWithoutDeployedContracts = mockInvalidCtxWithoutDeployedContracts();
        try {
            eosBBCService.startup(mockInvalidCtxWithoutDeployedContracts);
        }catch (Exception e){
            e.printStackTrace();
        }

        // start up failed with wrong url
        AbstractBBCContext mockInvalidCtxWithWrongUrl = mockInvalidCtxWithWrongUrl();
        try {
            eosBBCService.startup(mockInvalidCtxWithWrongUrl);
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    @Test
    public void testShutdown(){
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);
        eosBBCService.shutdown();
    }

    @Test
    public void testGetContext(){
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

        AbstractBBCContext ctx = eosBBCService.getContext();
        Assert.assertNotNull(ctx);
        Assert.assertNotNull(ctx.getAuthMessageContract());
        Assert.assertNotNull(ctx.getSdpContract());
        Assert.assertEquals(EOS_AM_CONTRACT_NAME, ctx.getAuthMessageContract().getContractAddress());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getAuthMessageContract().getStatus());
    }

    @Test
    public void testSetupAuthMessageContract(){
        // start up
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

        // set up am
        eosBBCService.setupAuthMessageContract();

        // get context
        AbstractBBCContext ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getAuthMessageContract().getStatus());
    }

    @Test
    public void testSetupSDPMessageContract(){
        // start up
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

        // set up sdp
        eosBBCService.setupSDPMessageContract();

        // get context
        AbstractBBCContext ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getSdpContract().getStatus());
    }

    @Test
    public void testReadCrossChainMessageReceipt() throws IOException, InterruptedException {
        relayAmPrepare();

        // todo： relay am msg
        // CrossChainMessageReceipt crossChainMessageReceipt = eosBBCService.relayAuthMessage(getRawMsgFromRelayer());
        //
        // System.out.println("sleep 15s for tx to be packaged...");
        // Thread.sleep(WAIT_TIME);

        // read receipt by txHash
        CrossChainMessageReceipt crossChainMessageReceipt1 = eosBBCService.readCrossChainMessageReceipt("16aeae2899ddeaeac23f616858322d6a9ca073d03ba55130a8e4e22ace696106");
        Assert.assertTrue(crossChainMessageReceipt1.isSuccessful());
        //Assert.assertEquals(crossChainMessageReceipt.isSuccessful(), crossChainMessageReceipt1.isSuccessful());
    }

    @Test
    public void testReadCrossChainMessagesByHeight_sendUnordered() throws Exception {
        relayAmPrepare();

        // 1. set sdp addr
        // todo

        // 2. send msg
        // todo

        // 3. query latest height
//        long height1 = eosBBCService.queryLatestHeight();
//
//        System.out.println("sleep 15s for tx to be packaged...");
//        Thread.sleep(WAIT_TIME);
//
//        long height2 = eosBBCService.queryLatestHeight();

        long height1 = 203;
        long height2 = 203;

        // 4. read cc msg
        List<CrossChainMessage> messageList = ListUtil.toList();
        for(long i = height1; i <= height2; i++){
            messageList.addAll(eosBBCService.readCrossChainMessagesByHeight(i));
        }
        Assert.assertEquals(1, messageList.size());
        Assert.assertEquals(CrossChainMessage.CrossChainMessageType.AUTH_MSG, messageList.get(0).getType());
    }

    @Test
    public void testQueryLatestHeight(){
        relayAmPrepare();
        Assert.assertNotEquals(0, eosBBCService.queryLatestHeight().longValue());
    }

    @Test
    public void testInvokeHello(){
        relayAmPrepare();
        Assert.assertTrue(eosBBCService.demoInvokeHello());
    }

    @Test
    public void testInvokeSetData(){
        relayAmPrepare();
        Assert.assertEquals(10, eosBBCService.demoInvokeSetData());
    }

    /*@Test
    public void testQuerySDPMessageSeq(){
        // start up
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

        // set up sdp
        eosBBCService.setupSDPMessageContract();

        // set the domain
        eosBBCService.setLocalDomain("receiverDomain");

        // query seq
        long seq = eosBBCService.querySDPMessageSeq(
                "senderDomain",
                DigestUtil.sha256Hex("senderID"),
                "receiverDomain",
                DigestUtil.sha256Hex("receiverID")
        );
        Assert.assertEquals(0L, seq);
    }

    @Test
    public void testSetProtocol() throws Exception {
        // start up
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

        // set up am
        eosBBCService.setupAuthMessageContract();

        // set up sdp
        eosBBCService.setupSDPMessageContract();

        // get context
        AbstractBBCContext ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getAuthMessageContract().getStatus());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getSdpContract().getStatus());

        // set protocol to am (sdp type: 0)
        eosBBCService.setProtocol(
                ctx.getSdpContract().getContractAddress(),
                "0");

        String addr = AuthMsg.load(
                eosBBCService.getBbcContext().getAuthMessageContract().getContractAddress(),
                eosBBCService.getWeb3j(),
                eosBBCService.getCredentials(),
                new DefaultGasProvider()
        ).getProtocol(BigInteger.ZERO).send();
        System.out.printf("protocol: %s\n", addr);

        // check am status
        ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_READY, ctx.getAuthMessageContract().getStatus());
    }

    @Test
    public void testSetAmContractAndLocalDomain() throws Exception {
        // start up
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

        // set up am
        eosBBCService.setupAuthMessageContract();

        // set up sdp
        eosBBCService.setupSDPMessageContract();

        // get context
        AbstractBBCContext ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getAuthMessageContract().getStatus());
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getSdpContract().getStatus());

        // set am to sdp
        eosBBCService.setAmContract(ctx.getAuthMessageContract().getContractAddress());

        String amAddr = SDPMsg.load(
                eosBBCService.getBbcContext().getSdpContract().getContractAddress(),
                eosBBCService.getWeb3j(),
                eosBBCService.getCredentials(),
                new DefaultGasProvider()
        ).getAmAddress().send();
        System.out.printf("amAddr: %s\n", amAddr);

        // check contract status
        ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_DEPLOYED, ctx.getSdpContract().getStatus());

        // set the domain
        eosBBCService.setLocalDomain("receiverDomain");

        byte[] rawDomain = SDPMsg.load(
                eosBBCService.getBbcContext().getSdpContract().getContractAddress(),
                eosBBCService.getWeb3j(),
                eosBBCService.getCredentials(),
                new DefaultGasProvider()
        ).getLocalDomain().send();
        System.out.printf("domain: %s\n", HexUtil.encodeHexStr(rawDomain));

        // check contract status
        ctx = eosBBCService.getContext();
        Assert.assertEquals(ContractStatusEnum.CONTRACT_READY, ctx.getSdpContract().getStatus());
    }

    @Test
    public void testRelayAuthMessage() throws Exception {
        relayAmPrepare();

        // relay am msg
        CrossChainMessageReceipt receipt = eosBBCService.relayAuthMessage(getRawMsgFromRelayer());
        Assert.assertTrue(receipt.isSuccessful());

        System.out.println("sleep 15s for tx to be packaged...");
        Thread.sleep(WAIT_TIME);

        EthGetTransactionReceipt ethGetTransactionReceipt = eosBBCService.getWeb3j().ethGetTransactionReceipt(receipt.getTxhash()).send();
        TransactionReceipt transactionReceipt = ethGetTransactionReceipt.getTransactionReceipt().get();
        Assert.assertNotNull(transactionReceipt);
        Assert.assertTrue(transactionReceipt.isStatusOK());
    }

    @Test
    public void testReadCrossChainMessagesByHeight_sendOrdered() throws Exception {
        relayAmPrepare();

        // 1. set sdp addr
        TransactionReceipt receipt = appContract.setProtocol(eosBBCService.getBbcContext().getSdpContract().getContractAddress()).send();
        if (receipt.isStatusOK()){
            System.out.printf("set protocol(%s) to app contract(%s) \n",
                    appContract.getContractAddress(),
                    eosBBCService.getBbcContext().getSdpContract().getContractAddress());
        } else {
            throw new Exception(String.format("failed to set protocol(%s) to app contract(%s)",
                    appContract.getContractAddress(),
                    eosBBCService.getBbcContext().getSdpContract().getContractAddress()));
        }

        // 2. send msg
        try {
            // 2.1 create function
            List<Type> inputParameters = new ArrayList<>();
            inputParameters.add(new Utf8String("remoteDomain"));
            inputParameters.add(new Bytes32(DigestUtil.sha256(REMOTE_APP_CONTRACT)));
            inputParameters.add(new DynamicBytes("CrossChainMessage".getBytes()));
            Function function = new Function(
                    AppContract.FUNC_SENDMESSAGE, // function name
                    inputParameters, // inputs
                    Collections.emptyList() // outputs
            );
            String encodedFunc = FunctionEncoder.encode(function);

            // 2.2 pre-execute before commit tx
            EthCall call = eosBBCService.getWeb3j().ethCall(
                    Transaction.createEthCallTransaction(
                            eosBBCService.getCredentials().getAddress(),
                            appContract.getContractAddress(),
                            encodedFunc
                    ),
                    DefaultBlockParameterName.LATEST
            ).send();

            // 2.3 async send tx
            EthSendTransaction ethSendTransaction = eosBBCService.getRawTransactionManager().sendTransaction(
                    BigInteger.valueOf(eosBBCService.getConfig().getGasPrice()),
                    BigInteger.valueOf(eosBBCService.getConfig().getGasLimit()),
                    appContract.getContractAddress(),
                    encodedFunc,
                    BigInteger.ZERO
            );

            System.out.printf("send ordered msg tx %s\n", ethSendTransaction.getTransactionHash());
        } catch (Exception e) {
            throw new RuntimeException(
                    String.format("failed to send ordered msg"), e
            );
        }

        // 3. query latest height
        long height1 = eosBBCService.queryLatestHeight();

        System.out.println("sleep 15s for tx to be packaged...");
        Thread.sleep(WAIT_TIME);

        long height2 = eosBBCService.queryLatestHeight();

        // 4. read cc msg
        List<CrossChainMessage> messageList = ListUtil.toList();
        for(long i = height1; i <= height2; i++){
            messageList.addAll(eosBBCService.readCrossChainMessagesByHeight(i));
        }
        Assert.assertEquals(1, messageList.size());
        Assert.assertEquals(CrossChainMessage.CrossChainMessageType.AUTH_MSG, messageList.get(0).getType());
    }*/

    private void relayAmPrepare(){
        // start up
        AbstractBBCContext mockValidCtx = mockValidCtx();
        eosBBCService.startup(mockValidCtx);

//        // set up am
//        eosBBCService.setupAuthMessageContract();
//
//        // set up sdp
//        eosBBCService.setupSDPMessageContract();
//
//        // set protocol to am (sdp type: 0)
//        eosBBCService.setProtocol(
//                mockValidCtx.getSdpContract().getContractAddress(),
//                "0");
//
//        // set am to sdp
//        eosBBCService.setAmContract(mockValidCtx.getAuthMessageContract().getContractAddress());
//
//        // set local domain to sdp
//        eosBBCService.setLocalDomain("receiverDomain");
//
//        // check contract ready
//        AbstractBBCContext ctxCheck = eosBBCService.getContext();
//        Assert.assertEquals(ContractStatusEnum.CONTRACT_READY, ctxCheck.getAuthMessageContract().getStatus());
//        Assert.assertEquals(ContractStatusEnum.CONTRACT_READY, ctxCheck.getSdpContract().getStatus());
    }

    private AbstractBBCContext mockValidCtx(){
        EosConfig mockConf = new EosConfig();
        mockConf.setUrl(VALID_URL);
        mockConf.setUserPriKey(EOS_DEFAULT_PRIVATE_KEY);
        mockConf.setAmContractAddressDeployed(EOS_AM_CONTRACT_NAME);
        mockConf.setSdpContractAddressDeployed(EOS_SDP_CONTRACT_NAME);

        // todo: detete
        mockConf.setHelloContractAddressDeployed("helloa");
        mockConf.setGetDataContractAddressDeployed("lydata");
        mockConf.setUserName("liyuan");

        AbstractBBCContext mockCtx = new DefaultBBCContext();
        mockCtx.setConfForBlockchainClient(mockConf.toJsonString().getBytes());

        return mockCtx;
    }

    private AbstractBBCContext mockInvalidCtxWithWrongUrl(){
        EosConfig mockConf = new EosConfig();
        mockConf.setUrl(INVALID_URL);
        mockConf.setUserPriKey(EOS_DEFAULT_PRIVATE_KEY);
        AbstractBBCContext mockCtx = new DefaultBBCContext();
        mockCtx.setConfForBlockchainClient(mockConf.toJsonString().getBytes());
        return mockCtx;
    }

   private AbstractBBCContext mockInvalidCtxWithoutDeployedContracts(){
        EosConfig mockConf = new EosConfig();
        mockConf.setUrl(VALID_URL);
        mockConf.setUserPriKey(EOS_DEFAULT_PRIVATE_KEY);
        AbstractBBCContext mockCtx = new DefaultBBCContext();
        mockCtx.setConfForBlockchainClient(mockConf.toJsonString().getBytes());
        return mockCtx;
    }

    private AbstractBBCContext mockValidCtxWithPreReadyContracts(){
        EosConfig mockConf = new EosConfig();
        mockConf.setUrl(VALID_URL);
        mockConf.setUserPriKey(EOS_DEFAULT_PRIVATE_KEY);
        mockConf.setAmContractAddressDeployed(EOS_AM_CONTRACT_NAME);
        mockConf.setSdpContractAddressDeployed(EOS_SDP_CONTRACT_NAME);
        AbstractBBCContext mockCtx = new DefaultBBCContext();
        mockCtx.setConfForBlockchainClient(mockConf.toJsonString().getBytes());

        AuthMessageContract authMessageContract = new AuthMessageContract();
        authMessageContract.setContractAddress(EOS_AM_CONTRACT_NAME);
        authMessageContract.setStatus(ContractStatusEnum.CONTRACT_READY);
        mockCtx.setAuthMessageContract(authMessageContract);

        SDPContract sdpContract = new SDPContract();
        sdpContract.setContractAddress(EOS_SDP_CONTRACT_NAME);
        sdpContract.setStatus(ContractStatusEnum.CONTRACT_READY);
        mockCtx.setSdpContract(sdpContract);

        return mockCtx;
    }

/*

    private byte[] getRawMsgFromRelayer() throws IOException {
        ISDPMessage sdpMessage = SDPMessageFactory.createSDPMessage(
                1,
                "receiverDomain",
                HexUtil.decodeHex(
                        String.format("000000000000000000000000%s", appContract.getContractAddress().replaceAll("0x", ""))
                ),
                -1,
                "awesome antchain-bridge".getBytes()
        );

        IAuthMessage am = AuthMessageFactory.createAuthMessage(
                1,
                DigestUtil.sha256("senderID"),
                0,
                sdpMessage.encode()
        );

        MockResp resp = new MockResp();
        resp.setRawResponse(am.encode());

        MockProof proof = new MockProof();
        proof.setResp(resp);
        proof.setDomain("senderDomain");

        byte[] rawProof = TLVUtils.encode(proof);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(new byte[]{0, 0, 0, 0});

        int len = rawProof.length;
        stream.write((len >>> 24) & 0xFF);
        stream.write((len >>> 16) & 0xFF);
        stream.write((len >>> 8) & 0xFF);
        stream.write((len) & 0xFF);

        stream.write(rawProof);

        return stream.toByteArray();
    }

    @Getter
    @Setter
    public static class MockProof {

        @TLVField(tag = 5, type = TLVTypeEnum.BYTES)
        private MockResp resp;

        @TLVField(tag = 9, type = TLVTypeEnum.STRING)
        private String domain;
    }

    @Getter
    @Setter
    public static class MockResp {

        @TLVField(tag = 0, type = TLVTypeEnum.BYTES)
        private byte[] rawResponse;
    }*/
}
