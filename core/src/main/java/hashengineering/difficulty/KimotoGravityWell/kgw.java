package hashengineering.difficulty.KimotoGravityWell;

import java.lang.UnsatisfiedLinkError;
/**
 * Created by HashEngineering on 3/7/14.
 *
 * Native implimenation requires three methods to be called
 *  - init  - before the loop
 *  - loop2 - for each iteration of the loop
 *  - close - at the end of the loop and it returns the calculated difficulty
 */
public class kgw {
    private static boolean native_library_loaded = false;
    static {
        try {
            System.loadLibrary("kgw");
            native_library_loaded = true;
        }
        catch(UnsatisfiedLinkError e)
        {
            //no need to do anything here, the native_library_loaded value will be false
        }
        catch(Exception e)
        {

        }
    }
    public static boolean isNativeLibraryLoaded() { return native_library_loaded; }
    public static native byte[] KimotoGravityWell_close();

    public static native int KimotoGravityWell_init(long _TargetBlocksSpacingSeconds, long _PastBlocksMin, long _PastBlocksMax, double deviationDenominator);
    public static native int KimotoGravityWell_loop(int i, byte[] BlockReadingDiff, int BlockReadingHeight, long BlockReadingTime, long BlockLastSolvedTime);
    public static native int KimotoGravityWell_loop2(int i, long BlockReadingDiff, int BlockReadingHeight, long BlockReadingTime, long BlockLastSolvedTime);

    //todo::Refactor the entire algorithm here (native and hybrid)
}
