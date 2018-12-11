# xml-sec
demo project for apache xmlsec and BouncyCastle Provider usage

dependencies
```
<dependency>
    <groupId>org.apache.santuario</groupId>
    <artifactId>xmlsec</artifactId>
    <version>2.0.8</version>
</dependency>
<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.60</version>
</dependency>
```

use BouncyCastle to do RSA for XMLSignature, see `BcSignatureAlgorithm`

this is a SpringBoot Project, but it can be used as an dependency,
```
<dependency>
    <groupId>com.honey</groupId>
	<artifactId>xml-sec</artifactId>
	<version>0.0.1-SNAPSHOT</version>
    <exclusions>
        <exclusion>
            <groupId>org.springframework.boot</groupId>
            <artifactId>*</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```
