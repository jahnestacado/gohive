package gohive

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/beltran/gosasl"
	"github.com/go-zookeeper/zk"
	"github.com/jahnestacado/gohive/hiveserver"
)

const DEFAULT_FETCH_SIZE int64 = 1000
const ZOOKEEPER_DEFAULT_NAMESPACE = "hiveserver2"

// Connection holds the information for getting a cursor to hive
type Connection struct {
	host                string
	port                int
	username            string
	database            string
	auth                string
	kerberosServiceName string
	password            string
	sessionHandle       *hiveserver.TSessionHandle
	client              *hiveserver.TCLIServiceClient
	configuration       *ConnectConfiguration
	transport           thrift.TTransport
}

// ConnectConfiguration is the configuration for the connection
// The fields have to be filled manually but not all of them are required
// Depends on the auth and kind of connection.
type ConnectConfiguration struct {
	Username             string
	Principal            string
	Password             string
	Service              string
	HiveConfiguration    map[string]string
	PollIntervalInMillis int
	FetchSize            int64
	TransportMode        string
	HTTPPath             string
	TLSConfig            *tls.Config
	ZookeeperNamespace   string
	Database             string
	Timeout              time.Duration
}

// NewConnectConfiguration returns a connect configuration, all with empty fields
func NewConnectConfiguration() *ConnectConfiguration {
	return &ConnectConfiguration{
		Username:             "",
		Password:             "",
		Service:              "",
		HiveConfiguration:    nil,
		PollIntervalInMillis: 200,
		FetchSize:            DEFAULT_FETCH_SIZE,
		TransportMode:        "binary",
		HTTPPath:             "cliservice",
		TLSConfig:            nil,
		ZookeeperNamespace:   ZOOKEEPER_DEFAULT_NAMESPACE,
		Timeout:              10 * time.Second,
	}
}

// Connect to zookeper to get hive hosts and then connect to hive.
// hosts is in format host1:port1,host2:port2,host3:port3 (zookeeper hosts).
func ConnectZookeeper(ctx context.Context, hosts string, auth string,
	configuration *ConnectConfiguration) (conn *Connection, err error) {
	// consider host as zookeeper quorum
	zkHosts := strings.Split(hosts, ",")
	zkConn, _, err := zk.Connect(zkHosts, time.Second)
	if err != nil {
		return nil, err
	}

	hsInfos, _, err := zkConn.Children("/" + configuration.ZookeeperNamespace)
	if err != nil {
		panic(err)
	}
	if len(hsInfos) > 0 {
		nodes := parseHiveServer2Info(hsInfos)
		rand.Shuffle(len(nodes), func(i, j int) {
			nodes[i], nodes[j] = nodes[j], nodes[i]
		})
		for _, node := range nodes {
			port, err := strconv.Atoi(node["port"])
			if err != nil {
				continue
			}
			conn, err := innerConnect(ctx, node["host"], port, auth, configuration)
			if err != nil {
				// Let's try to connect to the next one
				continue
			}
			return conn, nil
		}
		return nil, fmt.Errorf("all Hive servers of the specified Zookeeper namespace %s are unavailable",
			configuration.ZookeeperNamespace)
	} else {
		return nil, fmt.Errorf("no Hive server is registered in the specified Zookeeper namespace %s",
			configuration.ZookeeperNamespace)
	}

}

// Connect to hive server
func Connect(ctx context.Context, host string, port int, auth string,
	configuration *ConnectConfiguration) (conn *Connection, err error) {
	return innerConnect(ctx, host, port, auth, configuration)
}

func parseHiveServer2Info(hsInfos []string) []map[string]string {
	results := make([]map[string]string, len(hsInfos))
	actualCount := 0

	for _, hsInfo := range hsInfos {
		validFormat := false
		node := make(map[string]string)

		for _, param := range strings.Split(hsInfo, ";") {
			kvPair := strings.Split(param, "=")
			if len(kvPair) < 2 {
				break
			}
			if kvPair[0] == "serverUri" {
				hostAndPort := strings.Split(kvPair[1], ":")
				if len(hostAndPort) == 2 {
					node["host"] = hostAndPort[0]
					node["port"] = hostAndPort[1]
					validFormat = len(node["host"]) != 0 && len(node["port"]) != 0
				} else {
					break
				}
			} else {
				node[kvPair[0]] = kvPair[1]
			}
		}
		if validFormat {
			results[actualCount] = node
			actualCount++
		}
	}
	return results[0:actualCount]
}

func innerConnect(ctx context.Context, host string, port int, auth string,
	configuration *ConnectConfiguration) (conn *Connection, err error) {
	var socket thrift.TTransport
	if configuration.TLSConfig != nil {
		socket, err = thrift.NewTSSLSocketTimeout(fmt.Sprintf("%s:%d", host, port), configuration.TLSConfig, configuration.Timeout)
	} else {
		socket, err = thrift.NewTSocketTimeout(fmt.Sprintf("%s:%d", host, port), configuration.Timeout)
	}

	if err != nil {
		return
	}

	if err = socket.Open(); err != nil {
		return
	}

	var transport thrift.TTransport

	if configuration == nil {
		configuration = NewConnectConfiguration()
	}
	if configuration.Username == "" {
		_user, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("Can't determine the username")
		}
		configuration.Username = strings.Replace(_user.Name, " ", "", -1)
	}
	// password may not matter but can't be empty
	if configuration.Password == "" {
		configuration.Password = "x"
	}

	if configuration.TransportMode == "http" {
		if auth == "NONE" {
			httpClient, protocol, err := getHTTPClient(configuration)
			if err != nil {
				return nil, err
			}
			httpOptions := thrift.THttpClientOptions{Client: httpClient}
			transport, err = thrift.NewTHttpClientTransportFactoryWithOptions(fmt.Sprintf(protocol+"://%s:%s@%s:%d/"+configuration.HTTPPath, url.QueryEscape(configuration.Username), url.QueryEscape(configuration.Password), host, port), httpOptions).GetTransport(socket)
			if err != nil {
				return nil, err
			}
		} else if auth == "KERBEROS" {
			mechanism, err := gosasl.NewGSSAPIMechanism(configuration.Service)
			if err != nil {
				return nil, err
			}
			saslClient := gosasl.NewSaslClient(host, mechanism)
			token, err := saslClient.Start()
			if err != nil {
				return nil, err
			}
			if len(token) == 0 {
				return nil, fmt.Errorf("Gssapi init context returned an empty token. Probably the service is empty in the configuration")
			}

			httpClient, protocol, err := getHTTPClient(configuration)
			if err != nil {
				return nil, err
			}
			httpClient.Jar = newCookieJar()

			httpOptions := thrift.THttpClientOptions{
				Client: httpClient,
			}
			transport, err = thrift.NewTHttpClientTransportFactoryWithOptions(fmt.Sprintf(protocol+"://%s:%d/"+configuration.HTTPPath, host, port), httpOptions).GetTransport(socket)
			httpTransport, ok := transport.(*thrift.THttpClient)
			if ok {
				httpTransport.SetHeader("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
			}
			if err != nil {
				return nil, err
			}
		} else {
			panic("Unrecognized auth")
		}
	} else if configuration.TransportMode == "binary" {
		if auth == "NOSASL" {
			transport = thrift.NewTBufferedTransport(socket, 4096)
			if transport == nil {
				return nil, fmt.Errorf("BufferedTransport was nil")
			}
		} else if auth == "NONE" || auth == "LDAP" || auth == "CUSTOM" {
			saslConfiguration := map[string]string{"username": configuration.Username, "password": configuration.Password}
			transport, err = NewTSaslTransport(socket, host, "PLAIN", saslConfiguration)
			if err != nil {
				return
			}
		} else if auth == "KERBEROS" {
			saslConfiguration := map[string]string{"service": configuration.Service}
			transport, err = NewTSaslTransport(socket, host, "GSSAPI", saslConfiguration)
			if err != nil {
				return
			}
		} else if auth == "DIGEST-MD5" {
			saslConfiguration := map[string]string{"username": configuration.Username, "password": configuration.Password, "service": configuration.Service}
			transport, err = NewTSaslTransport(socket, host, "DIGEST-MD5", saslConfiguration)
			if err != nil {
				return
			}
		} else {
			panic("Unrecognized auth")
		}
		if !transport.IsOpen() {
			if err = transport.Open(); err != nil {
				return
			}
		}
	} else {
		panic(fmt.Sprintf("Unrecognized transport mode %s", configuration.TransportMode))
	}

	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	client := hiveserver.NewTCLIServiceClientFactory(transport, protocolFactory)

	openSession := hiveserver.NewTOpenSessionReq()
	openSession.ClientProtocol = hiveserver.TProtocolVersion_HIVE_CLI_SERVICE_PROTOCOL_V6
	openSession.Configuration = configuration.HiveConfiguration
	openSession.Username = &configuration.Username
	openSession.Password = &configuration.Password
	response, err := client.OpenSession(ctx, openSession)
	if err != nil {
		return
	}

	database := configuration.Database
	if database == "" {
		database = "default"
	}
	connection := &Connection{
		host:                host,
		port:                port,
		database:            database,
		auth:                auth,
		kerberosServiceName: "",
		sessionHandle:       response.SessionHandle,
		client:              client,
		configuration:       configuration,
		transport:           transport,
	}

	if configuration.Database != "" {
		_, err := execute(ctx, connection, "USE "+configuration.Database)
		if err != nil {
			return nil, err
		}
	}

	return connection, nil
}

func getHTTPClient(configuration *ConnectConfiguration) (httpClient *http.Client, protocol string, err error) {
	if configuration.TLSConfig != nil {
		transport := &http.Transport{TLSClientConfig: configuration.TLSConfig}
		httpClient = &http.Client{Transport: transport}
		protocol = "https"
	} else {
		httpClient = http.DefaultClient
		protocol = "http"
	}
	return
}

// Close closes a session
func (c *Connection) Close(ctx context.Context) error {
	closeRequest := hiveserver.NewTCloseSessionReq()
	closeRequest.SessionHandle = c.sessionHandle
	responseClose, err := c.client.CloseSession(ctx, closeRequest)

	if c.transport != nil {
		errTransport := c.transport.Close()
		if errTransport != nil {
			return errTransport
		}
	}
	if err != nil {
		return err
	}
	if !success(responseClose.GetStatus()) {
		return fmt.Errorf("Error closing the session: %s", responseClose.Status.String())
	}
	return nil
}

func Exec(ctx context.Context, connection *Connection, query string) error {
	_, err := execute(ctx, connection, query)
	return err
}

func Query(ctx context.Context, connection *Connection, query string) (*hiveserver.TFetchResultsResp, int, error) {
	responseExecute, err := execute(ctx, connection, query)
	if err != nil {
		return nil, 0, err
	}
	fetchRequest := hiveserver.NewTFetchResultsReq()
	fetchRequest.OperationHandle = responseExecute.OperationHandle
	fetchRequest.Orientation = hiveserver.TFetchOrientation_FETCH_NEXT
	fetchRequest.MaxRows = connection.configuration.FetchSize
	responseFetch, err := connection.client.FetchResults(ctx, fetchRequest)
	if err != nil {
		return nil, 0, err
	}

	if responseFetch.Status.StatusCode != hiveserver.TStatusCode_SUCCESS_STATUS {
		return nil, 0, fmt.Errorf(responseFetch.Status.String())
	}

	totalRows, err := getTotalRows(responseFetch.Results.GetColumns())
	if err != nil {
		return nil, 0, err
	}

	return responseFetch, totalRows, nil

}

func execute(ctx context.Context, connection *Connection, query string) (*hiveserver.TExecuteStatementResp, error) {
	executeReq := hiveserver.NewTExecuteStatementReq()
	executeReq.SessionHandle = connection.sessionHandle
	executeReq.Statement = query
	var responseExecute *hiveserver.TExecuteStatementResp
	responseExecute, err := connection.client.ExecuteStatement(ctx, executeReq)
	if err != nil {
		return nil, err
	}

	if !success(responseExecute.GetStatus()) {
		return nil, fmt.Errorf("Error while executing query: %s", responseExecute.Status.String())
	}

	return responseExecute, nil
}

func success(status *hiveserver.TStatus) bool {
	statusCode := status.GetStatusCode()
	return statusCode == hiveserver.TStatusCode_SUCCESS_STATUS || statusCode == hiveserver.TStatusCode_SUCCESS_WITH_INFO_STATUS
}

type inMemoryCookieJar struct {
	given   *bool
	storage map[string][]http.Cookie
}

func (jar inMemoryCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		jar.storage["cliservice"] = []http.Cookie{*cookie}
	}
	*jar.given = false
}

func (jar inMemoryCookieJar) Cookies(u *url.URL) []*http.Cookie {
	cookiesArray := []*http.Cookie{}
	for pattern, cookies := range jar.storage {
		if strings.Contains(u.String(), pattern) {
			for i := range cookies {
				cookiesArray = append(cookiesArray, &cookies[i])
			}
		}
	}
	if !*jar.given {
		*jar.given = true
		return cookiesArray
	} else {
		return nil
	}
}

func newCookieJar() inMemoryCookieJar {
	storage := make(map[string][]http.Cookie)
	f := false
	return inMemoryCookieJar{&f, storage}
}

func getTotalRows(columns []*hiveserver.TColumn) (int, error) {
	for _, el := range columns {
		if el.IsSetBinaryVal() {
			return len(el.BinaryVal.Values), nil
		} else if el.IsSetByteVal() {
			return len(el.ByteVal.Values), nil
		} else if el.IsSetI16Val() {
			return len(el.I16Val.Values), nil
		} else if el.IsSetI32Val() {
			return len(el.I32Val.Values), nil
		} else if el.IsSetI64Val() {
			return len(el.I64Val.Values), nil
		} else if el.IsSetBoolVal() {
			return len(el.BoolVal.Values), nil
		} else if el.IsSetDoubleVal() {
			return len(el.DoubleVal.Values), nil
		} else if el.IsSetStringVal() {
			return len(el.StringVal.Values), nil
		} else {
			return -1, fmt.Errorf("Unrecognized column type %T", el)
		}
	}
	return 0, fmt.Errorf("All columns seem empty")
}
