package Practica1;

import BCprovider.*;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

public class p1main {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider())



    }
}
