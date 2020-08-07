package Util;

import java.awt.*;

/**
 Collected constants of general utility.

 <P>All members of this class are immutable.

 <P>(This is an example of
 <a href='http://www.javapractices.com/Topic2.cjp'>class for constants</a>.)
 */
public final class Consts  {

    // Cover/Secret
    public static final int COVER_IMAGE = 0;
    public static final int SECRET_IMAGE = 1;

    //SharedPreferences
    public static final String SHARED_PREF_NAME = "cryptomessenger_spref";
    public static final String PREF_COVER_PATH = "cover_image_pref";
    public static final String PREF_COVER_IS_SET = "cover_is_set_pref";

    //Stego Image Map Keys
    public static final String MESSAGE_TYPE = "message_type";
    public static final String MESSAGE_BITS = "message_bits";

    // Secret Message Types
    public static final int TYPE_TEXT = 0;
    public static final int TYPE_IMAGE = 1;
    public static final int TYPE_UNDEFINED = 2;

    //Bundle arguments
    public static final String EXTRA_STEGO_IMAGE_PATH = "stego_image_path";
    public static final String EXTRA_SECRET_TEXT_RESULT = "secret_text_result";
    public static final String EXTRA_SECRET_IMAGE_RESULT = "secret_image_result";

    //Colors for Stego Image. They are the most rare colors in nature
    public static final Color COLOR_RGB_END = new Color(96, 62, 148); //Saint's Row Purple
    public static final Color COLOR_RGB_TEXT = new Color(135, 197, 245); //Killfom (Baby Blue)
    public static final Color COLOR_RGB_IMAGE = new Color(255, 105, 180); //Hot pink

    /** Opposite of {@link #FAILS}.  */
    public static final boolean PASSES = true;
    /** Opposite of {@link #PASSES}.  */
    public static final boolean FAILS = false;

    /** Opposite of {@link #FAILURE}.  */
    public static final boolean SUCCESS = true;
    /** Opposite of {@link #SUCCESS}.  */
    public static final boolean FAILURE = false;

    /**
     Useful for {@link String} operations, which return an index of <tt>-1</tt> when
     an item is not found.
     */
    public static final int NOT_FOUND = -1;

    /** System property - <tt>line.separator</tt>*/
    public static final String NEW_LINE = System.getProperty("line.separator");
    /** System property - <tt>file.separator</tt>*/
    public static final String FILE_SEPARATOR = System.getProperty("file.separator");
    /** System property - <tt>path.separator</tt>*/
    public static final String PATH_SEPARATOR = System.getProperty("path.separator");

    public static final String EMPTY_STRING = "";
    public static final String SPACE = " ";
    public static final String TAB = "\t";
    public static final String SINGLE_QUOTE = "'";
    public static final String PERIOD = ".";
    public static final String DOUBLE_QUOTE = "\"";
    public static final int PORT = 0;
    public static final String SERVER_NAME = "";

    // PRIVATE //

    /**
     The caller references the constants using <tt>Consts.EMPTY_STRING</tt>,
     and so on. Thus, the caller should be prevented from constructing objects of
     this class, by declaring this private constructor.
     */
    private Consts(){
        //this prevents even the native class from
        //calling this ctor as well :
        throw new AssertionError();
    }
}
