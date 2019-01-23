package com.firefly.modules.db.leveldb;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.fusesource.leveldbjni.JniDBFactory;
import org.iq80.leveldb.CompressionType;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.DBComparator;
import org.iq80.leveldb.Options;

import java.io.File;
import java.io.IOException;

/**
 * @author Jiawei Chan
 * @date 2019-01-23
 */
public class User {
    public static void main(String[] args) {
        Options options = new Options();
        options.createIfMissing(true);
        options.comparator(new DBComparator() {
            @Override
            public String name() {
                return "hex comparator";
            }

            @Override
            public byte[] findShortestSeparator(byte[] start, byte[] limit) {
                return new byte[0];
            }

            @Override
            public byte[] findShortSuccessor(byte[] key) {
                return new byte[0];
            }

            @Override
            public int compare(byte[] o1, byte[] o2) {
                return HexBin.encode(o1).compareTo(HexBin.encode(o2));
            }
        });
        options.logger(message -> System.out.println("MyDB: " + message));
        options.compressionType(CompressionType.NONE);
        options.cacheSize(100 * 1048576);

        DB db = null;
        try {
            db = JniDBFactory.factory.open(new File("C:\\Users\\chenjw\\Desktop\\MyDB"), options);

            db.put(JniDBFactory.bytes("db"), JniDBFactory.bytes("leveldb"));
            System.out.println("db: " + JniDBFactory.asString(db.get(JniDBFactory.bytes("db"))));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (db != null) {
                    db.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
