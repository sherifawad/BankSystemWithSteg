package algorithm.Steganograpgy;

//import com.sun.istack.internal.Nullable;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.Random;

public class Embedding {

    /**
     * Embeds secret text inside the cover image in the following way:
     * 1) Copy the entire cover image as ARGB_8888 with pre-multiplied feature = false
     * 2) Convert secret text into stream of bits stored as String
     * 3) Check if this stream of bits can be fit inside the cover image, return null otherwise
     * 4) Generate 24 bit random key represented as integer array of length 24 and store in (0,0)th pixel
     * 5) Set flag that indicates the type of secret message (text) in (0,1)th pixel of stego image
     * 6) Perform embedding of secret message stream of bits in the following way:
     *      i) Initialize 2 nested for-loops in respective interval [0 <= x <= width],[2 <= y <= height]
     *      ii) Select each pixel of stego image from (x,y) coordinates
     *      iii) Extract Red, Green, Blue colors from each pixel and store in integer array
     *      iv) Store 1 bit of secret text in each of the colors. Decision of which color to choose
     *          is conducted by xor operation of one bit of random key and 2nd LSB of stego image.
     *          If xor equals to 1 then we store that bit, otherwise we skip the color.
     *      v)  Update the pixel of stego image at (x,y) with above mutated RGB colors
     *      iv) Repeat above given steps until the whole secret text as stream of bits is embedded
     * 7) Set flag which indicates the end of secret text in (x',y')th pixel,
     *    where x' and 'y are coordinates of next to the last mutated pixel
     * @param coverImage is a Bitmap image which is used to store secret image in
     * @param secretText is a String text which is stored inside cover image
     * @return Stego image as Bitmap, whose pixels are mutated in step 6)
     */

//    public static final int COLOR_RGB_END = Color.rgb(96, 62, 148); //Saint's Row Purple
//    public static final int COLOR_RGB_TEXT = Color.rgb(135, 197, 245); //Killfom (Baby Blue)

     public static final Color COLOR_RGB_END = new Color(96, 62, 148);//Saint's Row Purple
    public static final Color COLOR_RGB_TEXT = new Color(135, 197, 245); //Killfom (Baby Blue)

    public static final BufferedImage clone(BufferedImage image) {
        BufferedImage clone = new BufferedImage(image.getWidth(),
                image.getHeight(), image.getType());
        Graphics2D g2d = clone.createGraphics();
        g2d.drawImage(image, 0, 0, null);
        g2d.dispose();
        return clone;
    }

    public static BufferedImage embedSecretText(String secretText, BufferedImage coverImage) {
        BufferedImage stegoImage = clone(coverImage);

//        Bitmap stegoImage = coverImage.copy(Bitmap.Config.ARGB_8888, true);
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
//            stegoImage.setPremultiplied(false);
//        }

        String sTextInBin = HelperMethods.stringToBinaryStream(secretText);

        int secretMessageLen = sTextInBin.length();
        int action, embMesPos = 0, keyPos = 0;

        int width = coverImage.getWidth();
        int height = coverImage.getHeight();

        //If secret message is too long (3 bits in each pixel + skipping of some pixels)
        if (secretMessageLen > width * height * 2) {
            return null;
        }

        //Generate and place random 24 bit array of 0-1 in (0,0) pixel
        int key[] = generateKey();
        int temp_number;

        int red_sum = 0;
        for (int j = 0; j <= 7; ++j) {
            if (key[j] == 1) {
                temp_number = (int) Math.pow(2, 7 - j);
            } else {
                temp_number = 0;
            }
            red_sum += temp_number;
        }

        int green_sum = 0;
        for (int j = 8; j <= 15; ++j) {
            if (key[j] == 1) {
                temp_number = (int) Math.pow(2, 15 - j);
            } else {
                temp_number = 0;
            }
            green_sum += temp_number;
        }

        int blue_sum = 0;
        for (int j = 16; j <= 23; ++j) {
            if (key[j] == 1) {
                temp_number = (int) Math.pow(2, 23 - j);
            } else {
                temp_number = 0;
            }
            blue_sum += temp_number;
        }

        //Update (0,1) pixel with RGB_888 as for key values
//        stegoImage.setPixel(0, 0, Color.rgb(red_sum, green_sum, blue_sum));
        stegoImage.setRGB(0, 0, new Color(red_sum, green_sum, blue_sum).getRGB());
//        com.example.sherif.Steganograpgy.StandardMethods.showLog("EMB", "Key1: " + red_sum + " " + green_sum + " " + blue_sum);
        System.out.printf("EMB", "Key1: " + red_sum + " " + green_sum + " " + blue_sum);
        System.out.printf("");

        //To check if secret message is text. (0,0,COLOR_RGB_TEXT)
//        stegoImage.setPixel(0, 1, COLOR_RGB_TEXT);
        stegoImage.setRGB(0, 1, COLOR_RGB_TEXT.getRGB());

        int endX = 0, endY = 2;

        outerloop:
        for (int x = 0; x < width; x++) {
            for (int y = 2; y < height; y++) {
//                int pixel = coverImage.get(x, y);
                int pixel = coverImage.getRGB(x, y);

                if (embMesPos < secretMessageLen) {
//                    int colors[] = {Color.red(pixel), Color.green(pixel), Color.blue(pixel)};
                    int colors[] = {(pixel >> 16) & 0xff, (pixel >> 8) & 0xff, (pixel) & 0xff};

                    for (int c = 0; c < 3; c++) {
                        if (embMesPos == secretMessageLen) {
                            break;
                        }

                        //Action for LSB
                        if ((key[keyPos] ^ LSB2(colors[c])) == 1) {
                            action = action(colors[c], sTextInBin.charAt(embMesPos));
                            colors[c] += action;
                            embMesPos++;
                            keyPos = (keyPos + 1) % key.length;
                        }
                    }

//                    int newPixel = Color.rgb(colors[0], colors[1], colors[2]);
//                    stegoImage.setPixel(x, y, newPixel);

                    Color newPixel = new Color(colors[0], colors[1], colors[2]);
                    stegoImage.setRGB(x, y, newPixel.getRGB());
                } else {

                    if (y < height - 1) {
                        endX = x;
                        endY = y + 1;
                    } else if (endX < width - 1) {
                        endX = x + 1;
                        endY = y;
                    } else {
                        endX = width - 1;
                        endY = height - 1;
                    }

                    break outerloop;
                }
            }
        }

        //End of secret message flag. (0,2,COLOR_RGB_END)
//        stegoImage.setPixel(endX, endY, COLOR_RGB_END);
        stegoImage.setRGB(endX, endY, COLOR_RGB_END.getRGB());

        return stegoImage;
    }

    /**
     * @param number is either Red, Green, or Blue presented as integer (0-255)
     * @return least significant bit, i.e. the left-most
     */
//    @Contract(pure = true)
    private static int LSB(int number) {
        return number & 1;
    }

    /**
     * @param number is either Red, Green, or Blue presented as integer (0-255)
     * @return second least significant bit, i.e. second to the left-most
     */
//    @Contract(pure = true)
    private static int LSB2(int number) {
        return (number >> 1) & 1;
    }

    /**
     * Determines correct action which should be performed on Red/Green/Blue color
     * If LSB is 1 and bit is 0, we need to subtract 1 to make LSB 0
     * Else if LSB is 0 and bit is 1, we need to add 1 to make LSB 1
     * Otherwise we do not perform any action, since LSB is the same as bit
     *
     * @param color is either Red, Green, or Blue presented as integer (0-255)
     * @param bit   is bit of secret message which should be hidden
     * @return a correct integer which is used in mutation of color +1, -1, or 0
     */
    private static int action(int color, char bit) {
        if (LSB(color) == 1 && bit == '0') {
            return -1;
        } else if (LSB(color) == 0 && bit == '1') {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Generates random 24 bit key
     *
     * @return integer array of length 24 consisting of random stream of bits
     */
    private static int[] generateKey() {
        final int[] bits = {0, 1};
        int[] result = new int[24];

        int n, i;
        Random random = new Random();

        for (i = 0; i < result.length; ++i) {
            n = random.nextInt(2);
            result[i] = bits[n];
        }
        return result;
    }

}
