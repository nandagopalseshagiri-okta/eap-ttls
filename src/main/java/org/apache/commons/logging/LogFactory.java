package org.apache.commons.logging;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public class LogFactory {
    public static Log getLog(Class c) {
        return new Log();
    }
}
