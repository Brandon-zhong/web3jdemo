package com.web3jdemo.bitcoinjdemo;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.Wallet;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * @author brandon
 * Created by brandon on 2018/8/27.
 */
public class BitCoinJDemo {

    public static List<String> getMnemonic(byte[] bytes) throws IOException, MnemonicException.MnemonicLengthException {
        List<String> mnemonic = new MnemonicCode().toMnemonic(bytes);
        return mnemonic;
    }


    /**
     * 获取随机序列
     *
     * @return
     */
    public static byte[] getRandomList(int numBytes) {
        SecureRandom secureRandom = new SecureRandom();
        //获取安全性的随机序列(熵)
        byte[] initialEntropy = new byte[numBytes];
        secureRandom.nextBytes(initialEntropy);
        return initialEntropy;
    }

    public static void test() throws IOException, MnemonicException.MnemonicLengthException {
        byte[] randomList = getRandomList(32);
        List<String> mnemonic = getMnemonic(randomList);
        System.out.println("mnemonic --> " + mnemonic);


        NetworkParameters params = TestNet3Params.get();
        DeterministicSeed deterministicSeed = new DeterministicSeed(mnemonic, null, "", Utils.currentTimeSeconds());
        Wallet wallet = Wallet.fromSeed(params, deterministicSeed);
        System.out.println(ReflectionToStringBuilder.toString(wallet, ToStringStyle.MULTI_LINE_STYLE));

    }

    public static void main(String[] args) {
        try {
            test();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (MnemonicException.MnemonicLengthException e) {
            e.printStackTrace();
        }

    }
}
