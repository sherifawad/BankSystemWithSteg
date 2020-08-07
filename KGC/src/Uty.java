import java.io.*;
import java.math.BigInteger;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;


public class Uty {
    public void zip(String zipFile, String[] srcFiles) {

        try {

            // create byte buffer
            byte[] buffer=new byte[1024];

            FileOutputStream fos=new FileOutputStream(zipFile);

            ZipOutputStream zos=new ZipOutputStream(fos);

            for (int i=0; i < srcFiles.length; i++) {

                File srcFile=new File(srcFiles[i]);

                FileInputStream fis=new FileInputStream(srcFile);

                // begin writing a new ZIP entry, positions the stream to the start of the entry data
                zos.putNextEntry(new ZipEntry(srcFile.getName()));

                int length;

                while ((length=fis.read(buffer)) > 0) {
                    zos.write(buffer, 0, length);
                }

                zos.closeEntry();

                // close the InputStream
                fis.close();

            }

            // close the ZipOutputStream
            zos.close();

        } catch (IOException ioe) {
            System.out.println("Error creating zip file: " + ioe);
        }

    }

    public void unZipIt(String zipFile, String outputFolder) {

        byte[] buffer=new byte[1024];

        try {

            //create output directory is not exists
            File folder=new File(outputFolder);
            if (!folder.exists()) {
                folder.mkdir();
            }

            //get the zip file content
            ZipInputStream zis=new ZipInputStream(new FileInputStream(zipFile));
            //get the zipped file list entry
            ZipEntry ze=zis.getNextEntry();

            while (ze != null) {

                String fileName=ze.getName();
                File newFile=new File(outputFolder + File.separator + fileName);

//                System.out.println("file unzip : "+ newFile.getAbsoluteFile());

                //create all non exists folders
                //else you will hit FileNotFoundException for compressed folder
                new File(newFile.getParent()).mkdirs();

                FileOutputStream fos=new FileOutputStream(newFile);

                int len;
                while ((len=zis.read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }

                fos.close();
                ze=zis.getNextEntry();
            }

            zis.closeEntry();
            zis.close();

//            System.out.println("Done");

        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }



    public BigInteger hashTObig(byte[][] data) {
        MessageDigest md =null;
        try {
            md=MessageDigest.getInstance("SHA-256");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        for (byte[] aByte : data) {
            md.update(aByte);
        }
        byte[] digest1 = md.digest();
        return new BigInteger(1, digest1);
    }


    public static BigInteger bytesHash(byte[] data) {
        MessageDigest md = null;
        byte[] digest1 = new byte[0];

        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(data);
            digest1 = md.digest();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return new BigInteger(1, digest1);
    }

    public static byte[] byteConcatenate(List<byte[]> data) {
        ByteArrayOutputStream outputStream;
        outputStream = new ByteArrayOutputStream();
        for (byte[] b : data) {
            outputStream.write(b, 0, b.length);
        }
        return outputStream.toByteArray();
    }



    public byte[] bEad(String FILENAME) {
        RandomAccessFile f=null;
        try {
            f=new RandomAccessFile(FILENAME, "r");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        byte[] b=new byte[0];
        try {
            b=new byte[(int) f.length()];
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            f.readFully(b);
            f.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
//        System.out.println(Arrays.toString(b));
        return b;

    }

    public static String sEad(String FILENAME) {
        String sCurrentLine="";
        String out="";
        BufferedReader br=null;
        try {
            br=new BufferedReader(new FileReader(FILENAME));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            while ((sCurrentLine=br.readLine()) != null) {
                //            System.out.println(sCurrentLine);
                out+=sCurrentLine;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return out;
    }


    public static void remove (Path directory) {

//            Path directory = Paths.get("/Users/pankaj/log");
        try {
            Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    Files.delete(file); // this will work because it's always a File
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir); //this will work because Files in the directory are already deleted
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public  ArrayList<byte[]> bigToarray(BigInteger number) {
        List<byte[]> out=new   ArrayList<>();
        out.add(number.toByteArray());
        return (ArrayList<byte[]>) out;
    }

    public BigInteger arrayTobig(ArrayList arrayList) {
        BigInteger out=new BigInteger((byte[]) arrayList.get(0));
        return out;

    }



    public static byte[] mapTOBytes(HashMap hmap) {
        ByteArrayOutputStream bos=new ByteArrayOutputStream();
        ObjectOutput out=null;
        byte[] hashBytes;
        try {
            try {
                out=new ObjectOutputStream(bos);
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                out.writeObject(hmap);
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
            hashBytes=bos.toByteArray();

        } finally {
            try {
                bos.close();
            } catch (IOException ex) {
            }
        }
        return hashBytes;
    }





    public static HashMap byteTOMap(byte[] hash_bytes) {

        ByteArrayInputStream byteIn=new ByteArrayInputStream(hash_bytes);
        ObjectInputStream in=null;
        HashMap<String, Object> newMap=null;

        try {
            in=new ObjectInputStream(byteIn);
            newMap=(HashMap<String, Object>) in.readObject();

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        finally {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return newMap;
    }


    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];

        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (((int) a[i]) ^ ((int) b[i]));
        }

        return result;
    }

    public static BigInteger randomBig(BigInteger range) {
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        BigInteger outRandomNumber = new BigInteger(range.bitLength(), random);


        return outRandomNumber;
    }

    static byte[] concatenate(byte[] data){
        byte[] array = new byte[0];
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            outputStream.write(data);
            array = outputStream.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return array;
    }


    public static String serialize(Serializable o) throws IOException {
        ByteArrayOutputStream baos = null;
        ObjectOutputStream oos = null;
        try {
            baos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(baos);
            oos.writeObject(o);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (oos != null) {
                oos.close();
            }
            if (baos != null) {
                baos.close();
            }
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }


    public static Object deserialize(String s) {
        Object o= null;
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = null;


        try {
            ois = new ObjectInputStream(
                    new ByteArrayInputStream(data));
            o = ois.readObject();

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            try {
                ois.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return o;
    }

    public static String currentDate(){

        Calendar calendar1 = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        SimpleDateFormat formatter1 = new SimpleDateFormat("dd/M/yyyy h:mm:ss");
        String currentDate = formatter1.format(calendar1.getTime());
        return currentDate;
    }

}
