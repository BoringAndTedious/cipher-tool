## openssl生成国密p10

1. 安装 openssl-3.0.0-beta1.tar.gz

   > [下载地址](https://github.com/openssl/openssl/releases/tag/openssl-3.0.0-beta1)

2. 查看openssl版本  openssl version

   > 低版本可能不支持 sm3WithSM2Sign算法

3. 检查修改openssl配置文件openssl.cnf ，修改[ req ] default_md  = sm3

   ```shell
   [ req ]
   default_bits            = 2048
   default_md              = sm3
   default_keyfile         = privkey.pem
   distinguished_name      = req_distinguished_name
   attributes              = req_attributes
   ```

4. 执行命令生成SM2私钥：

   ```shell
   openssl ecparam -genkey -name SM2  -out sm2Private.key 
   ```

5. 执行命令生成p10:

   ```shell
   openssl req  -key sm2Private.key  -new -out sm2P10.req -subj '/CN=Bank of ShangHai/OU=Enterprises/O=CFCA SM2 OC3A1/C=CN'
   ```
   > **-key 引用第4步生成的SM2私钥文件**
   > **-subj 为userDn:  cn:主题名称；ou：部门；o：组织；c：国家。**
   > **一个userDn或一个SM2私钥只能申请一次证书。申请新的证书请重新生成SM2私钥及重新生成的p10文件。**

6. 查看p10文件：

   ```shell
   cat sm2P10.req
   ```
6. 查看私钥文件：

   ```shell
   cat sm2Private.key
   ```
   
8. 生成证书curl

   ```shell
   curl -X POST "http://192.9.200.238:10010/platCert/applyCert" -H "Request-Origion:SwaggerBootstrapUi" -H "accept:*/*" -H "Content-Type:application/json" -d "{\"acaBeginDate\":\"2021-08-01\",\"acaCsrCert\":\"-----BEGIN%20CERTIFICATE%20REQUEST-----%0AMIIBFzCBvwIBADBcMR4wHAYDVQQDDBVCYW5rIG9mIFNoYW5nSGFpQFRlc3QxFDAS%0ABgNVBAsMC0VudGVycHJpc2VzMRcwFQYDVQQKDA5DRkNBIFNNMiBPQzNBMTELMAkG%0AA1UEBhMCQ04wWjAUBggqgRzPVQGCLQYIKoEcz1UBgi0DQgAEx35X71tz0dYNBQgM%0As8qH1vaeU3%2FedhtTLmQz%2FPYRX0CzE%2B2IAE7ZlgkNX0oLugPpoGU%2FeGEqNStGlMv9%0A8aoGzKAAMAoGCCqBHM9VAYN1A0cAMEQCIDLj2fkGZAuUYQGeQLL1rsXVWFIPyw6U%0AsWTHMorArq0cAiACbyVmb2unqEP9sb12VdcvM%2FllqzewUSxxpfmVMjf6qA%3D%3D%0A-----END%20CERTIFICATE%20REQUEST-----\",\"acaEndDate\":\"2023-08-01\",\"acaIdentNo\":\"123456789215145846\",\"acaIdentType\":\"0\",\"acaUserName\":\"admin\",\"entName\":\"测试证书\"}"
   ```

   > acaBeginDate 开始时间，acaEndDate 结束时间，acaCsrCert URLdecode后的P10，acaIdentNo 证件号码，
   >
   > acaIdentType 证件类型，acaUserName 用户名称，entName证书名称

