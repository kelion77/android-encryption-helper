package lee.sungjin.keystore;

import android.content.Context;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;
import lee.sungjin.keystore.core.EncryptionHelper;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {

    final String testString = "test string.";

//    @Test
//    public void useAppContext() {
//        // Context of the app under test.
//        Context appContext = InstrumentationRegistry.getTargetContext();
//
//        assertEquals("lee.sungjin.keystore", appContext.getPackageName());
//    }

    @Test
    public void encrypt() {
        EncryptionHelper encryptionHelper = EncryptionHelper.getInstance();
        EncryptionHelper.getInstance().deleteKeyPair();

        Assert.assertFalse(encryptionHelper.keyPairExists());

//        encryptionHelper.setValue("test",testString);
//        // then decrypt (if it's in other test, it will loose in-memory stuff
//        String returnValue = encryptionHelper.getValue("test");
        String encryptedString = encryptionHelper.encryptMessage(testString);
        String decryptedString = encryptionHelper.decryptMessage(encryptedString);
        Assert.assertEquals(testString, decryptedString);

    }

}
