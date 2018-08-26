package com.web3jdemo;


import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.admin.Admin;
import org.web3j.protocol.admin.methods.response.PersonalUnlockAccount;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;
import rx.Subscription;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * @author brandon
 * Created by brandon on 2018/8/22.
 */
public class Demo {

    private static final String BRANDON_ADDRESS = "0x1e8df9b23c3c9952b0f26ce093a2c4c016f7d287";

    private static final String BRANDON_PRIVATE_KEY = "6685086E502283408384BA9B472F1FD0105F56F4CFF9EE81CD5F6F0FF8AD689B";

    private static final String ZHONG_ADDRESS = "0x9d49d8eacb8ee66b03c3f845210b0613a965cc62";

    private static final String ZHONG_PRIVATE_KEY = "FA4FB7F0983FA6873138D859C4549E6D28D165263FB4EA41038A30C1C1A84542";

    private static final Web3j web3j = Web3j.build(new HttpService("https://ropsten.infura.io/v3/a3f0e7feded142f8854a3c2a6e05bf35"));

    private static final Admin admin = Admin.build(new HttpService("https://ropsten.infura.io/v3/a3f0e7feded142f8854a3c2a6e05bf35"));

    private static int i = 0;

    /**
     * privateKey --> 36046190667066833575095047186211601444752191542148689753758321596955059373678
     * privateKey(Hex) --> 4fb16bc14fb52c6db1985af3cc8b1e389413d6469831b77d12875fdd72e1466e
     * publicKey --> 3509524920480187970161804108497367890885638428619222570555171255987982644802242426705364869514305313510775837540481825686317403340338519812298505830053623
     * address --> 172f1e7f526e60ea09420b14b919659f853102cd
     * mnemonic --> exile mercy utility panda fan cycle shoe area video gold shy illness donkey twenty bounce alert resist trigger peace sausage strong idle boost shop
     *
     * @param args
     * @throws ExecutionException
     * @throws InterruptedException
     * @throws TimeoutException
     * @throws IOException
     */
    public static void main(String[] args) throws ExecutionException, InterruptedException, TimeoutException, IOException {

        String fromAddress = "0x7997c99218B7f39bC4cE5404220919Cd3d5c6E90";
        String fromPrivateKey = "9e01703375cfb07f7a417b3c40350f2879bdd1a994ff262d69f8caec8597698f";

        String toAddress = "0x172f1e7f526e60ea09420b14b919659f853102cd";
        String toPrivateKey = "4fb16bc14fb52c6db1985af3cc8b1e389413d6469831b77d12875fdd72e1466e";

        getBalanceByAddr(fromAddress);
        getBalanceByAddr(toAddress);

        transactions(fromAddress, toAddress, "6", fromPrivateKey);

        Thread.sleep(200000);

        getBalanceByAddr(fromAddress);
        getBalanceByAddr(toAddress);

//        mnemonic();

//        getPrivatekey();
//        web3j.shutdown();
    }

    /**
     * 获取eth当前区块高度
     *
     * @throws ExecutionException
     * @throws InterruptedException
     */
    public static void getEthBlockNumber() throws ExecutionException, InterruptedException {
        BigInteger blockNumber = web3j.ethBlockNumber().sendAsync().get().getBlockNumber();
        System.out.println("ethBlockNumber --> " + blockNumber);
    }

    /**
     * 获取eth手续费的当前价值
     *
     * @throws ExecutionException
     * @throws InterruptedException
     */
    public static void getEthGasPrice() throws ExecutionException, InterruptedException {
        BigInteger gasPrice = web3j.ethGasPrice().sendAsync().get().getGasPrice();
        System.out.println("ethGasPrice --> " + gasPrice);
    }

    public static String transactions(String fromAddress, String toAddress, String number, String fromPrivateKey) throws InterruptedException, ExecutionException, TimeoutException, IOException {
        //设置需要的矿工费
        BigInteger gas_price = BigInteger.valueOf(22_000_000_000L);
        BigInteger gas_limit = BigInteger.valueOf(4_300_000);

        //获取该地址私钥的验证
        Credentials credentials = Credentials.create(fromPrivateKey);
        //获取该地址的nonce值
        BigInteger nonce = getNonceLatest(fromAddress);
        //创建交易
        BigDecimal value = Convert.toWei(number, Convert.Unit.ETHER);
        RawTransaction etherTransaction = RawTransaction.createEtherTransaction(nonce, gas_price, gas_limit, toAddress, value.toBigInteger());

        //对交易签名
        byte[] signMessage = TransactionEncoder.signMessage(etherTransaction, credentials);
        String hexValue = Numeric.toHexString(signMessage);

        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).sendAsync().get();

        String transactionHash = ethSendTransaction.getTransactionHash();

        System.out.println("transactionHash --> " + transactionHash);

        return transactionHash;
    }

    public static void getTransactionByAddress(String transactionHash) throws ExecutionException, InterruptedException {
        org.web3j.protocol.core.methods.response.Transaction transaction = web3j.ethGetTransactionByHash(transactionHash).sendAsync().get().getTransaction().get();

        System.out.println("getTransactionByAddress --> " + ReflectionToStringBuilder.toString(transaction, ToStringStyle.MULTI_LINE_STYLE));
    }

    public static BigInteger getNonceLatest(String address) throws IOException {
        EthGetTransactionCount count = web3j.ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).send();
        return count.getTransactionCount();
    }


    /**
     * 根据eth地址获取该地址的余额
     *
     * @param address
     * @throws ExecutionException
     * @throws InterruptedException
     */
    public static void getBalanceByAddr(String address) throws ExecutionException, InterruptedException {
        BigInteger latest = web3j.ethGetBalance(address, DefaultBlockParameter.valueOf("latest")).sendAsync().get().getBalance();
        System.out.println("ethGetBalance --> " + latest);
    }


    //5743E843780254D22DC39E230C328FF75EEFBD9014EAB6B82A6DB1C5D9949F3A
    //5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn
    public static String getPrivatekey() {

//            ECKeyPair ecKeyPair = Keys.createEcKeyPair();
//            System.out.println("privateKey --> " + ecKeyPair.getPrivateKey());
//            System.out.println("publicKey --> " + ecKeyPair.getPublicKey());
//
//            String address = Keys.getAddress(ecKeyPair.getPublicKey());
//            System.out.println("address --> " + address);
//            byte[] bytes = ecKeyPair.getPrivateKey().toByteArray();
//            String mnemonic = getMnemonic(bytes);
//            System.out.println("mnemonic --> " + mnemonic + "\n");

        byte[] randomList = getRandomList(32);
        BigInteger bigInteger = Sign.publicKeyFromPrivate(new BigInteger(randomList));
        System.out.println("privateKey --> " + new BigInteger(randomList));
        System.out.println("privateKey(Hex) --> " + bytesToHexString(randomList).toLowerCase());
        System.out.println("publicKey --> " + bigInteger);

        String address = Keys.getAddress(bigInteger);
        System.out.println("address --> " + address);
        String mnemonic = getMnemonic(randomList);
        System.out.println("mnemonic --> " + mnemonic);


        return null;
    }

    //xprv9s21ZrQH143K3QtGFJpkoSb6PDSzrutYmqe2ArQmAYNh5adzTDEE2RgaF2DyyLZCWhxgxeKsyiAjw7iAGS9fxG6kVHwdZVMcAWYKTQ7v892
    //D7E1352A9F6732104ADED936405375C0C1B07AD3EB26E65472A26A56F8D81E6FA32A0348DF666354C7DC2627D6CB69D412B0482850FB96E6283F7347D714A709
    public static void mnemonic() {
        byte[] bytes = getRandomList(16);
        System.out.println(Arrays.toString(bytes) + "    length --> " + bytes.length);

//        String mnemonic = getMnemonic(bytes);
        String mnemonic = "economy bird same laptop property panic chat water calm hello noble bacon";
        System.out.println("MnemonicUtils --> " + mnemonic);

        byte[] seed = getSeedByMnemonicAndPassPhrase(mnemonic, "zhong6465");
        System.out.println("seed --> " + bytesToHexString(seed) + "    length --> " + seed.length);

        byte[] sha512 = sha512(seed);
        System.out.println("sha256 --> " + bytesToHexString(sha512) + "    length --> " + sha512.length);

        byte[] masterPrivateKey = Arrays.copyOfRange(sha512, 0, 256 / 8);
        System.out.println("masterPrivateKey --> " + bytesToHexString(masterPrivateKey));

        byte[] masterChainCode = Arrays.copyOfRange(sha512, 256 / 8, sha512.length);
        System.out.println("masterChainCode -->" + bytesToHexString(masterChainCode));
    }

    /**
     * 获取随机序列
     *
     * @return
     */
    public static byte[] getRandomList(int numBytes) {
        SecureRandom secureRandom = new SecureRandom();
        //获取安全性的随机序列(熵)
        byte[] bytes = secureRandom.generateSeed(numBytes);
        return bytes;
    }

    /**
     * 根据随机序列获取助记词
     *
     * @param bytes
     * @return
     */
    public static String getMnemonic(byte[] bytes) {
        String mnemonic = MnemonicUtils.generateMnemonic(bytes);
        return mnemonic;
    }

    /**
     * 根据助记词和密码获取种子
     *
     * @param mnemonic
     * @param passphrase
     * @return
     */
    public static byte[] getSeedByMnemonicAndPassPhrase(String mnemonic, String passphrase) {
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, passphrase);
        return seed;
    }


    public static void observableBlockChain() {
        Web3j web3j = Web3j.build(new HttpService("https://mainnet.infura.io/v3/a3f0e7feded142f8854a3c2a6e05bf35"));
        Subscription subscribe = web3j.blockObservable(false).subscribe(ethBlock -> {
            EthBlock.Block block = ethBlock.getResult();
            System.out.println("当前区块高度 --> " + block.getNumber() + "   上一个区块 --> " + block.getParentHash() + block.getHash());
        });
        System.out.println("订阅的 --> " + subscribe.hashCode());
    }

    /**
     * Generates SHA-256 digest for the given {@code input}.
     *
     * @param input The input to digest
     * @return The hash value for the given input
     * @throws RuntimeException If we couldn't find any SHA-256 provider
     */
    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Couldn't find a SHA-256 provider", e);
        }
    }

    /**
     * Generates SHA-256 digest for the given {@code input}.
     *
     * @param input The input to digest
     * @return The hash value for the given input
     * @throws RuntimeException If we couldn't find any SHA-512 provider
     */
    public static byte[] sha512(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Couldn't find a SHA-256 provider", e);
        }
    }

    /**
     * 将byte[]数组转换为十六进制字符串
     *
     * @param bArray
     * @return
     */
    public static final String bytesToHexString(byte[] bArray) {
        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

}
