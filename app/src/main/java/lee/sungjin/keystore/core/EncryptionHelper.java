package lee.sungjin.keystore.core;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import static lee.sungjin.keystore.MyApplication.getContext;

/**
 * Created on 25/8/18.
 */
public class EncryptionHelper {
    private static final String TAG = "EncryptionHelper";

    private static final String KEY_ENCRYPTION_ALGORITHM = "RSA";
    private static final String KEY_TRANSFORMATION_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_X500PRINCIPAL = "CN=Sung Lee, O=RapidGlobal, C=AU";
    private static final String KEY_CHARSET = "UTF-8";
    private static final String KEY_ALIAS = "EncryptionKey";   // if need more than 1 secretKey. should add meaningful name.

    private static final EncryptionHelper mInstance = new EncryptionHelper();

    private WeakReference<Context> mContext;

    private EncryptionHelper() {
        mContext = new WeakReference<Context>(getContext());
    }

    public static EncryptionHelper getInstance() {
        return mInstance;
    }

    @Nullable
    public String encryptMessage(@NonNull String plainMessage) {
        try {
            if (!keyPairExists()) {
                generateKeyPair();
            }
            Cipher input;
            // no need to have routine for Android M if use default.
            input = Cipher.getInstance(KEY_TRANSFORMATION_ALGORITHM);
            input.init(Cipher.ENCRYPT_MODE, getPublicKey());

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, input);
            cipherOutputStream.write(plainMessage.getBytes(KEY_CHARSET));
            cipherOutputStream.close();

            byte[] values = outputStream.toByteArray();
            return Base64.encodeToString(values, Base64.DEFAULT);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    @Nullable
    public String decryptMessage(@NonNull String encryptedMessage) {
        try {
            // message can't be decrypted if there's no keypair
            if (!keyPairExists()) {
                generateKeyPair();
                return null;
            }
            Cipher output;
            // no need to have routine for Android M if use default.
            output = Cipher.getInstance(KEY_TRANSFORMATION_ALGORITHM);
            output.init(Cipher.DECRYPT_MODE, getPrivateKey());

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encryptedMessage, Base64.DEFAULT)), output);
            List<Byte> values = new ArrayList<>();

            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) { //NOPMD
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            return new String(bytes, 0, bytes.length, KEY_CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Nullable
    private PublicKey getPublicKey() {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry) getKeyStoreInstance().getEntry(KEY_ALIAS, null);
            return privateKeyEntry.getCertificate().getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Nullable
    private PrivateKey getPrivateKey() {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry) getKeyStoreInstance().getEntry(KEY_ALIAS, null);
            return privateKeyEntry.getPrivateKey();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void deleteKeyPair() {
        try {
            getKeyStoreInstance().deleteEntry(KEY_ALIAS);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    /***
     * Initialize asymmetric key from Android Key Store
     * Only generate when it's not exist.
     */
    private void generateKeyPair() {
        if (!keyPairExists()) {
            try {
//            checking RTL not necessary
//            if (isRTL()) {
//                Locale.setDefault(Locale.US);
//            }
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 99);

                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext.get())
                        .setAlias(KEY_ALIAS)
                        .setSubject(new X500Principal(KEY_X500PRINCIPAL))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();

                KeyPairGenerator generator
                        = KeyPairGenerator.getInstance(KEY_ENCRYPTION_ALGORITHM, KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
                generator.initialize(spec);
                generator.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
                // handle exception
            }
        }
    }

//    private boolean isRTL() {
//        Configuration config = mContext.get().getResources().getConfiguration();
//        return config.getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
//    }

    private KeyStore getKeyStoreInstance() {
        try {
            // Get the AndroidKeyStore instance
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

            // if you do not have an input stream you want to load or it'll crash
            keyStore.load(null);

            return keyStore;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean keyPairExists() {
        try {
            return getKeyStoreInstance().getKey(KEY_ALIAS, null) != null;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
