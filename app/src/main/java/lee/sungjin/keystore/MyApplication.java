package lee.sungjin.keystore;

import android.app.Application;

/**
 * Created on 25/8/18.
 */
public class MyApplication extends Application {
    private static MyApplication mContext;

    public static MyApplication getContext() {
        return mContext;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        mContext = this;
    }
}
