// 小驼峰命名用来表示自定义变量, 并且只在这个package内使用，大驼峰命名的变量package外可用

package main

import (
	"fmt"
	"regexp"
	"net"
	"strings"
	"strconv"
	"crypto/md5"
)
//
/*
WWW-Authenticate  =  "WWW-Authenticate" HCOLON challenge
challenge           =  ("Digest" LWS digest-cln *(COMMA digest-cln))
                       / other-challenge
other-challenge     =  auth-scheme LWS auth-param
                       *(COMMA auth-param)
digest-cln          =  realm / domain / nonce
                        / opaque / stale / algorithm
                        / qop-options / auth-param
realm               =  "realm" EQUAL realm-value
realm-value         =  quoted-string
domain              =  "domain" EQUAL LDQUOT URI
                       *( 1*SP URI ) RDQUOT
URI                 =  absoluteURI / abs-path
nonce               =  "nonce" EQUAL nonce-value
nonce-value         =  quoted-string
opaque              =  "opaque" EQUAL quoted-string
stale               =  "stale" EQUAL ( "true" / "false" )
algorithm           =  "algorithm" EQUAL ( "MD5" / "MD5-sess"
                       / token )
qop-options         =  "qop" EQUAL LDQUOT qop-value
                       *("," qop-value) RDQUOT
qop-value           =  "auth" / "auth-int" / token
 */
// 401 Unauthorized message 中 WWW-Authenticate 字段
// belle-sip 直接用 ANTLAR 生成 parser, osip 没有依赖 parser generator
// 从 BNF 语法中可以看到它属于正则语法， 用正则表达式就能搞定
// 这里只用了 golang 自带的正则表达式, 功能比标准parser 弱
// 自己手写了一个 parser 复杂度为 O(n)
// 后来发现 golang 的正则表达式匹配复杂度也是 O(n)，就把自己手写的抛弃了

func parseAuth(line string, hashedMsg map[string]string){
	// 严格讲应该是 parseResult := regexp.MustCompile(`([a-zA-Z]+)=(?:")(.+?)\1`).FindAllStringSubmatch(line,-1) 保证引号配对，可惜 google 为了效率没有支持backreference
	parseResult := regexp.MustCompile(`([a-zA-Z]+)="(.+?)"`).FindAllStringSubmatch(line,-1)
	for _,x := range parseResult {
		hashedMsg[x[1]] = x[2]
	}
}

func md5Sum(s string) string{
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func dumpMsg(){

}

// 采用同步阻塞IO方式
// 没有完整实现RFC3261，目前只实现 REGISTER 过程
func main() {
	// input parameters
	user := "777"
	extension := 777
	pass := "abc123456"
	serverIPPort := "192.168.1.112:5060"

	conn, err := net.Dial("udp", serverIPPort)
	if err != nil {
		fmt.Println(err)
	}
	localAddr := conn.LocalAddr()
	localAddrStr := strings.Split(localAddr.String(),":")

	serverAddr := conn.RemoteAddr()
	serverAddrStr := strings.Split(serverAddr.String(),":")

	type Sess_t struct{
		serverIP   string
		serverPort int
		localIP    string
		localPort  int
		user       string
		pass       string
		extension  int
	}

	var sess Sess_t
	sess.serverIP 			= serverAddrStr[0]
	sess.serverPort, err 	= strconv.Atoi(serverAddrStr[1])
	sess.localIP 			= localAddrStr[0]
	sess.localPort, err 	= strconv.Atoi(localAddrStr[1])
    sess.user 				= user
    sess.pass 				= pass
    sess.extension 			= extension

    // REGISTER Request
	lines := []string{
		"REGISTER sip:%s:%d SIP/2.0\n",
		"Via: SIP/2.0/UDP %s:%d;branch=cbranch1\n",
		"Max-Forwards: 70\n",
		"To: %s <sip:%d@%s:%d>\n",
		"From: %s <sip:%d@%s:%d>;tag=456789\n",
		"Call-ID: ChangeToRandom\n",
		"CSeq: %d REGISTER\n",
		"Contact: %s <sip:%d@%s:%d>\n",
		"Expires: %d\n",
		"Content-Length: 0\n\n\n",
	}
	fmt1 := strings.Join(lines,"")
	registerRequest := fmt.Sprintf(fmt1, sess.localIP, sess.localPort,
		sess.serverIP, sess.serverPort,
		sess.user, sess.extension, sess.serverIP, sess.serverPort,
		sess.user, sess.extension, sess.serverIP, sess.serverPort,
		1,
		sess.user, sess.extension, sess.localIP, sess.localPort,
		3600)
	conn.Write([]byte(registerRequest))
    fmt.Println("send completed, and start recving 1")

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 5060,
	})

	data := make([]byte, 4096)
	_, _, err = ln.ReadFromUDP(data)

	// parse received message
	msgList :=strings.Split(string(data),"\r\n")

	// turn string formatted message to map data structure
	msgHashed :=make(map[string]string)
	for _, x := range msgList[1:]{
		colonpos:= strings.IndexByte(x,':')
		if colonpos > 0 {
			msgHashed[x[:colonpos]] = x[colonpos+2:]
		}
	}

	parseAuth((msgHashed["WWW-Authenticate"] + ",")[7:], msgHashed) // 默认用的是Digest，Basic明显有缺陷，密码容易被盗
	fmt.Println("analysis complete")

    // digest access authentication
	msgHashed["uri"] = "sip:" + sess.serverIP
	HA1:= user + ":" + msgHashed["realm"] + ":" + pass
	HA2:= "REGISTER" + ":" + msgHashed["uri"]
	msgHashed["responce"] = md5Sum(md5Sum(HA1) + ":" + msgHashed["nonce"] + ":" + md5Sum(HA2))

    // send credentials this time
	lines = []string{
		"REGISTER sip:%s:%d SIP/2.0\n",
		"Via: SIP/2.0/UDP %s:%d;branch=cbranch1\n",
		"Max-Forwards: 70\n",
		"To: %s <sip:%d@%s:%d>\n",
		"From: %s <sip:%d@%s:%d>;tag=456789\n",
		"Call-ID: ChangeToRandom\n",
		"CSeq: %d REGISTER\n",
		"Contact: %s <sip:%d@%s:%d>\n",
		"Expires: %d\n",
		"Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\n",
        `Authorization: Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=MD5
`,
		"Content-Length: 0\n\n\n",
	}
	fmt1 = strings.Join(lines,"")
	registerRequest = fmt.Sprintf(fmt1, sess.localIP, sess.localPort,
		sess.serverIP, sess.serverPort,
		sess.user, sess.extension, sess.serverIP, sess.serverPort,
		sess.user, sess.extension, sess.serverIP, sess.serverPort,
		2,
		sess.user, sess.extension, sess.localIP, sess.localPort,
		3600,
		sess.user, msgHashed["realm"], msgHashed["nonce"], msgHashed["uri"], msgHashed["responce"])
	fmt.Println(registerRequest)

	conn.Write([]byte(registerRequest))
	fmt.Println("send completed, and start recving 2")

	_, _, err = ln.ReadFromUDP(data)
	fmt.Printf("%s\n\n", data)

	for {
		n, err:=conn.Read(data)
		if err != nil {
			fmt.Println(err)
		}
		if n>0 {
			fmt.Printf("%s",data)
			dumpMsg()
			break
		}
	}
	conn.Close()
	ln.Close()

}
