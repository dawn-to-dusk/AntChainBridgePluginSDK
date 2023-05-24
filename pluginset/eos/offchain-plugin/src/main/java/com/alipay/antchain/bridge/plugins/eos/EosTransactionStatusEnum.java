package com.alipay.antchain.bridge.plugins.eos;

public enum EosTransactionStatusEnum {
    EXECUTED("executed"),
    SOFTFAIL("soft_fail"),
    HARDFAIL("hard_fail"),
    DELAYED("delayed"),
    EXPIRED("expired"),
    UNKNOW("unknow");

    private String status;

    EosTransactionStatusEnum(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }
}