/*
 
 Auth : Al Sabawi
 
 */

// System
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <ifaddrs.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#ifdef __linux__
#include <linux/sockios.h>
#include <linux/if_link.h>
#endif

#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <exception>
#include <fcntl.h>
#include <fstream>

// OpenSSL
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>


// MQueue
#include <mqueue.h>

#include<iostream>
#include<algorithm>
#include <string> 

// Boost C++ Lib
#include <boost/filesystem.hpp>
#include<boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>
#include<string>
#include "json.hpp"

using namespace std;
using namespace boost;
using json = nlohmann::json;
bool bDumpFile = false;
int process_request(int, unsigned char *, int, mqd_t, unsigned char *, int *, bool *);
int get_new_socket(char *);
int get_new_socket2();
int get_new_socket3(char *);
int wait_on_client(int *);
int wait_on_server(int *);
int server(int, char **);
int client(int, char **);
int enc_read(RSA *, int, unsigned char *, int, int);
int noenc_write(int, unsigned char *, int, int);
int noenc_read(int, unsigned char *, int, int);
int READ(RSA *, int, unsigned char *, int);
int WRITE(RSA *, int, unsigned char *, int);
int FIRST_READ(int, unsigned char *, int);
int FIRST_WRITE(int, unsigned char *, int);
int getmyip(int *, char ip_addr[10][40]);
//int write_encrypted_file(char *, EVP_PKEY *, char *);

int write_encrypted_file(unsigned char *, unsigned char *, char *);

int kencrypt(unsigned char *, int, unsigned char *,
	unsigned char *, unsigned char *);
int send_my_pubkey(void);

int sym_decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
int sym_encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
int sym_encrypt2(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);

int make_session_keys(unsigned char *, unsigned char *);

// Client process status
#define UNCONNECTED 0
#define HANDSHAKE 1
#define RUNNING_PROCESSING 2
#define RUNNING_WAITING 3


#define SERVERPORT "3490"  // the port users will be connecting to
#define SERVERPORT80 "80"
#define MQ_NAME "/mqqueue_in2"
#define MEMSIZE 32768
#define SERVER_STRING "Server: sabawi/0.1.0\r\n"
#define MQBUFFERSIZE 1024
#define NATIVE_PROTO    0
#define HTTP_PROTO      1
#define SSH_PROTO       2
#define DEFAULT_KETY_DIR "./ssh"
#define MAX_UNENCRYPTED_TEXT_SIZE (MEMSIZE - 1)
#define SCRIPTS_PATH "./scripts/"

static const unsigned int RANDOMKEY_SIZE = 32;
static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
static const unsigned int NAME_SIZE = 100;

int padding1 = RSA_PKCS1_PADDING;
int padding0 = RSA_NO_PADDING;

char privateKeyFile[] = ".ssh/private.pem";
char *privateKey = NULL;

typedef struct command_data {
    char parm_name[NAME_SIZE];
    char parm_value[NAME_SIZE];
    command_data *next;
} cmd_data, *pcmd_data;

typedef struct commands {
    char cmd[NAME_SIZE];
    pcmd_data pdata;
    commands *next;
} cmd, *pcmd;

typedef struct pshell {
    pid_t child_pid;
    int from_child, to_child, from_child_err;
} pipe_io;

typedef struct proc_golobals {
    RSA * my_private_rsa;
    RSA * peer_public_rsa;

    EVP_PKEY *EVP_key;
    unsigned char *session_key;
    int session_key_len;
    unsigned char * session_rsa;
    unsigned char * session_iv;

    unsigned char * mypublic_key_string;
    long mypublic_key_len;
    unsigned char * peer_public_key_string;
    long peer_public_key_len;

    int msg_q_id;
    int mypid;
    int client_sock;
    int client_status;
    char client_name[NAME_SIZE];

} proc_data, *pproc_data;

pcmd pCommandChain = NULL;
pproc_data pClientGlobals = NULL;

static inline std::string &ltrim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
	    std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end

static inline std::string &rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(),
	    std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// trim from both ends

static inline std::string &trim(std::string &s)
{
    return ltrim(rtrim(s));
}

static inline char *trimwhitespace(char *str)
{
    char *end;

    // Trim leading space
    while (isspace((unsigned char) *str)) str++;

    if (*str == 0) // All spaces?
	return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

bool is_file_executable(char *filename)
{
    if (!boost::filesystem::exists(filename))
    {
	return false;
    }
    struct stat st;

    if (stat(filename, &st) < 0)
	return false;
    if ((st.st_mode & S_IEXEC) != 0)
	return true;
    return false;
}

void *mymalloc(size_t s)
{
    try
    {
	void *m = malloc(s);
	if (m == NULL)
	{
	    cout << "Unable to allocate memory \n";
	    exit(-1);
	}
	else
	{
	    return m;
	}
    }

    catch (const std::runtime_error& re)
    {
	// speciffic handling for runtime_error
	std::cerr << "Runtime error: " << re.what() << std::endl;
    }
    catch (const std::exception& ex)
    {
	// speciffic handling for all exceptions extending std::exception, except
	// std::runtime_error which is handled explicitly
	std::cerr << "Error occurred: " << ex.what() << std::endl;
    }
    catch (...)
    {
	// catch any other errors (that we have no information about)
	std::cerr << "Unknown failure occurred. Possible memory corruption" << std::endl;
    }
}

pcmd new_command()
{
    pcmd p = (pcmd) mymalloc(sizeof(cmd));
    memset(p->cmd, 0, sizeof(p->cmd));
    p->pdata = NULL;
    p->next = NULL;
    return p;
}

int shell_pipe(char *cmdline, pipe_io *pio, int argc, char *const argv[])
{
    pid_t p;
    int pipe_stdin[2], pipe_stdout[2];
    string str_cmd;
    str_cmd = string(cmdline);
    str_cmd = trim(str_cmd);
    char *argv2[255];

    // build argument list 
    argv2[0] = "/bin/sh";
    argv2[1] = str_cmd.c_str();
    for (int i = 0; i < argc; i++)
	argv2[2 + i] = argv[i];
    argv2[2 + argc] = '\0';
    
    if (pipe(pipe_stdin)) return -1;
    if (pipe(pipe_stdout)) return -1;   
    
    p = fork();
    if (p < 0) return p; /* Fork failed */
    if (p == 0)
    { /* child */
	close(pipe_stdin[1]);
	dup2(pipe_stdin[0], 0);
	
	close(pipe_stdout[0]);
	dup2(pipe_stdout[1], 1);
	dup2(pipe_stdout[1], 2);
	
	execv("/bin/sh", argv2);
	perror("execl");
	exit(99);
    }

    //cout << "pipe parent ........." << endl;

    pio->child_pid = p;
    pio->to_child = pipe_stdin[1];
    pio->from_child = pipe_stdout[0];

    return 0;
}

std::string exec(const char* cmd, int argc, char *argv[])
{
    pipe_io pio;
    char buffer[MEMSIZE];
    string cmd2;
    
    cmd2.assign(cmd); //+ string("") + string("2>&1");
    cmd2 = string(SCRIPTS_PATH) + trim(cmd2);
    
    if(!is_file_executable(cmd2.c_str()))
    {	
	return "Error: Script does not exist or not executable";
    }
    
    try
    {
	cout << "About to execute : " << cmd2.c_str() << endl;
	shell_pipe(cmd2.c_str(), &pio, argc, argv);
	close(pio.to_child);
	memset(buffer, 0, MEMSIZE);
	read(pio.from_child, buffer, MEMSIZE);
    }
    catch (const std::exception& e)
    {
	perror("pipe");
	strcpy(buffer, "Error in pipe");
    }

    char *p = trimwhitespace(buffer);
    if (strlen(p) == 0)
	strcpy(buffer, "<EOL>");

    return buffer;
}

void hexdump(unsigned char *buffer, int buffer_len)
{
    unsigned char *xbuf = (unsigned char *) mymalloc((buffer_len * 4 * sizeof(unsigned char)) + 1);

    char t[2];
    for (int j = 0; j < buffer_len; j++)
    {
	sprintf(t, "%02x", (unsigned int) (buffer[j]));
	strcpy(&xbuf[2 * j], t);
	if (j % 28 == 0)
	{
	    sprintf(&xbuf[(2 * j) + 2], " \n");
	}
    }
    printf(xbuf);
    printf("\n");
    for (int i = 0; i < buffer_len; i++)
    {
	putchar(buffer[i]);
    }
    printf("\n");
    free(xbuf);
}

void force_no_encryption()
{
    // NOTE:
    // -- For NO encryption at all, NULL session_iv, session_rsa, and priv_rsa    
    // -- For Asym RSA encryption ONLY, NULL session_iv and session_rsa while comment out
    //    priv_rsa = NULL
    // -- For FULL encryption with noth Asym and Sym, comment out ALL Nulling lines below

    //pClientGlobals->session_iv = NULL;
    //pClientGlobals->session_rsa = NULL;
    //pClientGlobals->my_private_rsa = NULL;
}

pcmd_data new_command_data()
{
    pcmd_data p = (pcmd_data) mymalloc(sizeof(cmd_data));
    memset(p->parm_name, 0, sizeof(p->parm_name));
    memset(p->parm_value, 0, sizeof(p->parm_value));
    p->next = NULL;
    return p;
}

string makedirectory(string dirname, string indir)
{
    struct stat st = {0};

    if (dirname.empty() && indir.empty())
    {
	return "";
    }
    string newdir = dirname + "/" + indir;

    if (stat(newdir.c_str(), &st) == -1)
    {
	mkdir(newdir.c_str(), 0700);
    }

    return newdir;

}

void depleteSendBuffer(int fd)
{
#ifdef __linux__
    int lastOutstanding = -1;
    for (;;)
    {
	int outstanding;
	ioctl(fd, SIOCOUTQ, &outstanding);
	//        if (outstanding != lastOutstanding)
	//            printf("Outstanding: %d\n", outstanding);
	lastOutstanding = outstanding;
	if (!outstanding)
	    break;
	usleep(1000);
    }
#endif
}

//void init_openssl(void)
//{
//    if (SSL_library_init())
//    {
//	SSL_load_error_strings();
//	OpenSSL_add_all_algorithms();
//	RAND_load_file("/dev/urandom", 1024);
//    }
//    else
//	exit(EXIT_FAILURE);
//}

void cleanup_openssl(void)
{
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(0);
    EVP_cleanup();
}

void handle_openssl_error(void)
{
    fflush(stdout);

    printf("\n***ERROR***\n");
    ERR_print_errors_fp(stderr);
    printf("\n");
}

char *read_keyfile(char *file_name)
{
    char *source = NULL;
    FILE *fp = fopen(file_name, "r");
    if (fp != NULL)
    {
	/* Go to the end of the file. */
	if (fseek(fp, 0L, SEEK_END) == 0)
	{
	    /* Get the size of the file. */
	    long bufsize = ftell(fp);
	    if (bufsize == -1)
	    {
		/* Error */
	    }

	    /* Allocate our buffer to that size. */
	    source = (char *) mymalloc(sizeof(char) * (bufsize + 1));

	    /* Go back to the start of the file. */
	    if (fseek(fp, 0L, SEEK_SET) != 0)
	    {
		/* Error */
	    }

	    /* Read the entire file into memory. */
	    size_t newLen = fread(source, sizeof(char), bufsize, fp);
	    if (ferror(fp) != 0)
	    {
		fputs("Error reading file", stderr);
	    }
	    else
	    {
		source[newLen++] = '\0'; /* Just to be safe. */
	    }
	}
	fclose(fp);
    }
    return source;
}

long random_at_most(unsigned int min, unsigned int max)
{
    int r;
    const unsigned int range = 1 + max - min;
    const unsigned int buckets = RAND_MAX / range;
    const unsigned int limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do
    {
	r = rand();
    }
    while (r >= limit);

    return min + (r / buckets);
    ;
}

int generate_ascii_string(char * str, int max_len)
{
    int size = random_at_most(1, max_len);
    char buf[max_len];

    for (int i = 0; i < size; i++)
    {
	buf[i] = '0' + random_at_most(1, 255);

    }
    buf[size] = '\0';
    strcpy(str, buf);
    return size;
}

bool rsa_gen_keys_in_memory(RSA **rsakey, unsigned char **public_key_string, long * pklen, EVP_PKEY **pkey)
{
    int ret = 0;
    //BIO *bio_private = NULL;
    BIO *bio_public = NULL;
    int bits = 4096;

    //init_openssl();

    //char *private_key_text, *public_key_text;

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey2 = NULL;

    // Get the context
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
	goto cleanup;

    // init keygen
    if (EVP_PKEY_keygen_init(ctx) <= 0)
	goto cleanup;

    // set the bit size 
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
	goto cleanup;

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey2) <= 0)
	goto cleanup;

    *pkey = pkey2;

    *rsakey = EVP_PKEY_get1_RSA(*pkey);


    if (RSA_check_key(*rsakey))
    {
	printf("RSA key is valid.\n");
    }
    else
    {
	printf("Error validating RSA key.\n");
	handle_openssl_error();
	return false;
    }

    // write private key to memory
    //    bio_private = BIO_new(BIO_s_mem());
    //    ret = PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    //    if (ret != 1)
    //    {
    //	goto cleanup;
    //    }
    //    BIO_flush(bio_private);
    //    BIO_get_mem_data(bio_private, &private_key_text);
    //    cout << "PRIVE KEY :\n" << private_key_text << endl;



    // write public key to memory
    bio_public = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(bio_public, *pkey);
    if (ret != 1)
    {
	goto cleanup;
    }
    BIO_flush(bio_public);

    *pklen = BIO_get_mem_data(bio_public, public_key_string);

cleanup:

    //if (*pkey) EVP_PKEY_free(*pkey);

    cleanup_openssl();
    return ret;
}

bool rsa_gen_keys_to_file(unsigned char *password)
{
    int ret = 0;
    BIO *bio_private = NULL;
    BIO *bio_public = NULL;
    int bits = 4096;
    char randkeyfileName[40];
    char * strKey;

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    // Get the context
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
	goto cleanup;

    // init keygen
    if (EVP_PKEY_keygen_init(ctx) <= 0)
	goto cleanup;

    // set the bit size 
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
	goto cleanup;

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
	perror("Failed key generation ");
	goto cleanup;
    }
    if (generate_ascii_string(randkeyfileName, 39))
    {
	perror("Writing temp key file");
	goto cleanup;
    }

    // write rsa private key to file
    bio_private = BIO_new_file(randkeyfileName, "w+");
    ret = PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    if (ret != 1)
    {
	goto cleanup;
    }
    BIO_flush(bio_private);


    // write rsa public key to file
    bio_public = BIO_new_file(randkeyfileName, "w+");

    //ret = PEM_write_bio_RSAPublicKey(bio_public, rsa);
    ret = PEM_write_bio_PUBKEY(bio_public, pkey);
    if (ret != 1)
    {
	goto cleanup;
    }
    BIO_flush(bio_public);

    // Read private key as a text file 
    strKey = read_keyfile(randkeyfileName);

    write_encrypted_file(password, strKey, "encrypted_private_key.bin");
    unlink(randkeyfileName);

cleanup:
    if (bio_private) BIO_free_all(bio_private);
    if (bio_public) BIO_free_all(bio_public);
    if (pkey) EVP_PKEY_free(pkey);

    return ret;
}

int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
	n = noenc_read(sock, &c, 1, 0);
	/* DEBUG printf("%02X\n", c); */
	if (n > 0)
	{
	    if (c == '\r')
	    {
		n = noenc_read(sock, &c, 1, MSG_PEEK);
		/* DEBUG printf("%02X\n", c); */
		if ((n > 0) && (c == '\n'))
		    noenc_read(sock, &c, 1, 0);
		else
		    c = '\n';
	    }
	    buf[i] = c;
	    i++;
	}
	else
	    c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

void headers(int client, const char *filename)
{
    char buf[1024];
    (void) filename; /* could use filename to determine file type */

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    noenc_write(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */

/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    noenc_write(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    noenc_write(client, buf, strlen(buf), 0);
}

void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
	noenc_write(client, buf, strlen(buf), 0);
	fgets(buf, sizeof(buf), resource);
    }
}

int password2key(std::string password, const EVP_CIPHER *cipher, unsigned char *retkey, unsigned char *retiv)
{

    const EVP_MD *dgst = NULL;
    unsigned char ranpw[RANDOMKEY_SIZE];
    const unsigned char *salt = NULL;
    int ranpw_len = RANDOMKEY_SIZE;

    OpenSSL_add_all_digests();
    dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
	fprintf(stderr, "no such digest\n");
	return 1;
    }
    if (password.compare("randomrandom") == 0)
    {
	RAND_bytes(ranpw, ranpw_len);
	password.assign((const char *) ranpw);
	printf("Random password generated : %s\n", ranpw);
	fflush(stdout);
    }
    if (!EVP_BytesToKey(cipher, dgst, salt,
	    (unsigned char *) password.c_str(),
	    password.length(), 1, retkey, retiv))
    {
	fprintf(stderr, "EVP_BytesToKey failed\n");
	return 1;
    }

    return 0;
}

void getRandom(unsigned char *buf, int size)
{
    unsigned char buf2[size];
    int rc = RAND_bytes(buf2, size);

    unsigned long err = ERR_get_error();

    if (rc != 1)
    {
	perror("Random");
	printf("Error : %lu\n", err);
    }
    else
    {
	memcpy(buf, buf2, sizeof(buf2));
    }
}

int get_cipher_key(char *password, unsigned char *key, unsigned char *iv)
{

    // Load the necessary cipher
    EVP_add_cipher(EVP_aes_256_cbc());

    const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-256-cbc");

    password2key(password, cipher, key, iv);
}

int write_encrypted_file(unsigned char *password, unsigned char *buffer, char *file_name)
{

    int ciphertext_len;
    long textsize = strlen(buffer);
    unsigned char ciphertext[textsize];
    try
    {
	unsigned char key[KEY_SIZE], iv[BLOCK_SIZE];
	get_cipher_key(password, key, iv);

	cout << "Encrypting file ....";

	/* Encrypt the plaintext */
	ciphertext_len = kencrypt(buffer, textsize, key, iv, ciphertext);

	string outfile_name;
	outfile_name.assign(file_name);
	outfile_name.append(".sbn");

	// write to outfile
	fstream encrypted_file(outfile_name.c_str(), ios::out | ios::binary);
	encrypted_file.write((char *) ciphertext, ciphertext_len);
	cout << "File encrypted into '" << outfile_name << "'\n" << "Done!" << endl;
    }
    catch (std::exception e)
    {
	std::cerr << "Error occurred: " << e.what() << std::endl;
    }

    //free(plaintext);
}

int kencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_error();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	handle_openssl_error();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	handle_openssl_error();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_openssl_error();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_error();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	handle_openssl_error();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	handle_openssl_error();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handle_openssl_error();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int send_message_queue(mqd_t msgid, char *msg)
{
    int rc = 0;
    int msg_len = strlen(msg);
    int remaining = msg_len;
    int send_len = 0, msg_pos = 0;

    //    msg_len = (msg_len>1024)? 1024: msg_len;
    //    msg[msg_len] = '/0';
    // printf("MQ Message (to send) length = %d\n", msg_len);
    fflush(stdout);

    // Reject messages starting with NULL
    if (msg_len == 1)
    {
	// printf("MQ Send NULL message rejected\n");
	fflush(stdout);
	return 0;
    }
    while (remaining > 0)
    {
	//printf("MQ Length remaining = %d\n", remaining);
	send_len = (remaining >= MQBUFFERSIZE) ? MQBUFFERSIZE : remaining;

	rc = mq_send(msgid, &msg[msg_pos], send_len, 0);
	remaining -= send_len;
	msg_pos = msg_len - remaining - 1;
	// printf("*********MQ Send report:\nOriginal Msg Len = %d\nSend_len = %d\nRemaining = %d\nBuffer Position = %d\n***********\n",msg_len, send_len, remaining, (msg_pos) );
	if (rc < 0)
	{
	    perror("error mq_send");
	}
    }
    // printf(">>>>>>>>>MQ server message sent (%d bytes)\n", msg_pos+1);
    fflush(stdout);
    return rc;
}

void serve_file(int client, const char *filename)
{
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    // buf[0] = 'A'; buf[1] = '\0';
    // while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
    //  numchars = get_line(client, buf, sizeof(buf));

    resource = fopen(filename, "r");
    if (resource == NULL)
	not_found(client);
    else
    {
	headers(client, filename);
	cat(client, resource);
    }
    fclose(resource);
}

bool generate_asym_keys(EVP_PKEY** private_key, EVP_PKEY** public_key)
{
    bool ret = true;
    BIO *bio_private = NULL;
    BIO *bio_public = NULL;
    int bits = 4096;

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    // Get the context
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
	goto cleanup;

    // init keygen
    if (EVP_PKEY_keygen_init(ctx) <= 0)
	goto cleanup;

    // set the bit size 
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
	goto cleanup;

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, private_key) <= 0)
	goto cleanup;

cleanup:
    return ret;
}

bool pem_readkeyfile(char *filename, bool isPrivateKey, RSA **rsakey, EVP_PKEY** key)
{
    FILE* pFile = NULL;
    const EVP_CIPHER* pCipher = NULL;
    //EVP_PKEY* key;
    //init_openssl();
    *rsakey = NULL;

    /* Read the keys */
    if (isPrivateKey)
    {
	if ((pFile = fopen(filename, "rt")) &&
		(*key = PEM_read_PrivateKey(pFile, NULL, NULL, NULL)))
	{
	    fprintf(stderr, "Private key read.\n");
	}
	else
	{
	    fprintf(stderr, "Cannot read %s.\n", filename);
	    handle_openssl_error();
	    return false;
	}
	if (pFile)
	{
	    fclose(pFile);
	    pFile = NULL;
	}
    }
    else
    {
	if ((pFile = fopen(filename, "rt")) &&
		(*key = PEM_read_PUBKEY(pFile, NULL, NULL, NULL)))
	{
	    fprintf(stderr, "Public key read.\n");
	}
	else
	{
	    fprintf(stderr, "Cannot read %s.\n", filename);
	    handle_openssl_error();
	    return false;
	}
    }

    *rsakey = EVP_PKEY_get1_RSA(*key);

    if (isPrivateKey)
    {
	if (RSA_check_key(*rsakey))
	{
	    printf("RSA key is valid.\n");
	}
	else
	{
	    printf("Error validating RSA key.\n");
	    handle_openssl_error();
	    return false;
	}
    }
    cleanup_openssl();
    return true;
}

int main(int argc, char *argv[])
{
    //    long mypid;
    //    char ip_addr[10][40];
    //    int nips = 0;
    //
    //    mypid = getpid();
    //    getmyip(&nips, ip_addr);
    //    cout << "Starting on server(s) ";
    //    for(int i=0;i<nips;i++){
    //	if(i>0) cout << ", " ;  
    //	cout << ip_addr[i];
    //    }
    //    
    //    cout << endl;

    // Start listening server
    server(argc, argv);
    //_Exit(3);
    return 0;
}

int client(int argc, char *argv[])
{
    // printf("Internal MQ Client process started ... \n");

    //sleep(2);
    int rc = 1;
    key_t key = 0;
    mqd_t msgid = 0;
    char *msg = NULL;
    ssize_t rv = 0;
    bool quit = false;

    int mqmsg_size = MQBUFFERSIZE;
    //prctl(PR_SET_PDEATHSIG, SIGHUP);
    msg = (char*) mymalloc(mqmsg_size);
    if (!msg)
    {
	perror("malloc");
	goto cleanup;
    }

    memset(msg, 0, mqmsg_size);

    msgid = mq_open(MQ_NAME, O_RDONLY);
    if (msgid < 0)
    {
	perror("mq_open");
	goto cleanup;
    }
    try
    {
	//printf("MQ Client opened (max mesg size = %d)\n", mqmsg_size);
	while (!quit)
	{
	    // printf("Client Waiting for MQ message .. \n");
	    rv = mq_receive(msgid, msg, mqmsg_size, NULL);
	    //printf("<<<<<<<<<<(%d bytes) MQ Message received \n", rv);
	    if (rv < 0)
	    {
		perror("Eorror mq_receive");
		goto cleanup;
	    }
	    fflush(stdout);
	}
    }
    catch (int ex)
    {
	printf("Client exception receiving MQ Message\n");
	fflush(stdout);
    }
    rc = 0;
cleanup:
    if (msg)
    {
	free(msg);
	msg = NULL;
    }
    if (msgid > 0)
	mq_close(msgid);
    return rc;
}

mqd_t start_message_queue_client(int argc, char *argv[])
{
    // Create Message Queue
    int mqmsg_size = MQBUFFERSIZE;
    mqd_t msgid = 0;
    struct mq_attr mqattr;
    char *msg = NULL;

    msg = (char*) mymalloc(mqmsg_size);
    if (!msg)
    {
	perror("msg");
	return -1;
    }
    memset(msg, 0, mqmsg_size);
    strcpy(msg, "Hello from parent\0");
    mqattr.mq_flags = 0;
    mqattr.mq_maxmsg = 10;
    mqattr.mq_msgsize = mqmsg_size;
    mqattr.mq_curmsgs = 0;
    msgid = mq_open(MQ_NAME, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO, &mqattr);

    if (msgid < 0)
    {
	perror("mq_open");
	return -1;
    }

    //start MQ Local Client client
    int cpid = fork();
    if (!cpid)
    {
	// in child process
	strcpy(argv[0], "tcpInternalClient");
	prctl(PR_SET_NAME, "tcpInternalClient");
	client(argc, argv);
    }

    sleep(1);

    send_message_queue(msgid, msg);
    //mq_send(msgid, msg, strlen(msg), 0);
    //printf("MQ Server sent message \n");

    return msgid;
}

int HANDSHAKWITHECLIENT()
{
    int rc = 0, wrc = 0;
    bool quit = false;
    unsigned char *buf = NULL, *response = NULL;
    int response_len = 0;
    // Get incoming buffer memory
    buf = (unsigned char *) mymalloc(MEMSIZE * sizeof(unsigned char));
    memset(buf, 0, MEMSIZE);

    // Get response memory
    response = (unsigned char *) mymalloc(MEMSIZE * sizeof(unsigned char));
    memset(response, 0, MEMSIZE);

    if ((rc = FIRST_READ(pClientGlobals->client_sock, buf, MEMSIZE)) > 0)
    {
	pCommandChain = NULL;
	if (process_request(pClientGlobals->mypid,
		buf, pClientGlobals->client_sock,
		pClientGlobals->msg_q_id, response, &response_len, &quit)
		== 0)
	{
	    rc = false;
	    goto cleanup;
	}
	// Clear out incoming and outgoing buffers
	memset(buf, 0, MEMSIZE);
	memset(response, 0, MEMSIZE);
    }
    else
    {
	rc = false;
	goto cleanup;
    }
    rc = true;

cleanup:
    free(buf);
    free(response);
    return rc;
}

int getmyip(int *addr_count, char myipaddress[10][40])
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n, i = 0;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
    {
	perror("getifaddrs");
	exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
    {
	if (ifa->ifa_addr == NULL)
	    continue;

	family = ifa->ifa_addr->sa_family;

	if (family == AF_INET)
	{
	    s = getnameinfo(ifa->ifa_addr,
		    (family == AF_INET) ? sizeof(struct sockaddr_in) :
		    sizeof(struct sockaddr_in6),
		    host, NI_MAXHOST,
		    NULL, 0, NI_NUMERICHOST);
	    if (s != 0)
	    {
		printf("getnameinfo() failed: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	    }

	    if (strcmp(host, "127.0.0.1") != 0)
	    {
		strcpy(myipaddress[i], host);
		i++;
	    }
	    *addr_count = i;
	}
    }

    freeifaddrs(ifaddr);
}

int server(int argc, char *argv[])
{
    const char *socket_path = "\0hidden";
    char * portno = SERVERPORT;
    int fd, cl = 0, rc, s, wrc;
    unsigned char *buf = NULL, *response = NULL;
    int response_len = 0;
    long pid, mypid;
    pthread_t tid;
    int pthread;
    pthread_attr_t attr;
    int stack_size = MEMSIZE;
    bool encrypt = true;
    bool quit = false;
    mqd_t msgid = 0;
    RSA * svr_private_rsa = NULL;
    unsigned char * svr_public_key_string;
    long svr_public_key_len = 0;
    EVP_PKEY * svr_EVP_key = NULL;

    char ip_addr[10][40];
    int nips = 0;

    if (argc > 1)
    {
	portno = argv[1];
    }

    mypid = getpid();
    getmyip(&nips, ip_addr);
    cout << "Starting on server(s) ";
    for (int i = 0; i < nips; i++)
    {
	if (i > 0) cout << ", ";
	cout << ip_addr[i];
    }
    cout << " [" << portno << "]";
    cout << endl;

    struct sockaddr_in client_name;
    //int client_name_len = sizeof(client_name);

    for (int k = 1; k < argc; k++)
    {
	if (strcmp(argv[k], "noenc") == 0)
	    encrypt = false;
    }

    s = pthread_attr_init(&attr);
    s = pthread_attr_setstacksize(&attr, stack_size);

    // Generate server enc keys
    if (1 == rsa_gen_keys_in_memory(&svr_private_rsa, &svr_public_key_string,
	    &svr_public_key_len, &svr_EVP_key))
    {
	cout << "Found private key. Expecting encrypted communication.\n";
    }
    else
    {
	cout << "Expecting **unencrypted** communication.\n";
    }

    if (argc > 1) socket_path = argv[1];

    if ((fd = get_new_socket3(portno)) == -1)
    {
	perror("Unable to allocate scoket ");
	exit(-1);
    }

    // start message queue process
    //    if( (msgid = start_message_queue_client(argc, argv)) == -1)
    //    {
    //	printf("Failed to start mq client. returned -1\n");
    //	exit(-1);
    //    }

    if (listen(fd, 5) == -1)
    {
	perror("listen error");
	exit(-1);
    }

    cout << "Listening ..";
    fflush(stdout);

    while (((cl = accept(fd, NULL,
	    NULL)) != -1))
    {
	cout << "\n";
	pClientGlobals = NULL;

	/** Fork */
	pid = fork();
	if (!pid)
	{ // Child process
	    try
	    {
		close(fd); // Close parent socket

		pClientGlobals = (pproc_data) mymalloc(sizeof(proc_data));

		pClientGlobals->mypid = getpid();
		pClientGlobals->msg_q_id = msgid;
		pClientGlobals->client_sock = cl;
		pClientGlobals->client_status = HANDSHAKE;

		// populate server key info
		pClientGlobals->EVP_key = svr_EVP_key;
		pClientGlobals->my_private_rsa = svr_private_rsa;
		pClientGlobals->mypublic_key_string = svr_public_key_string;
		pClientGlobals->mypublic_key_len = svr_public_key_len;

		// init other crypto keys
		pClientGlobals->peer_public_rsa = NULL;
		pClientGlobals->session_iv = NULL;
		pClientGlobals->session_key = NULL;
		pClientGlobals->session_rsa = NULL;
		pClientGlobals->peer_public_key_len = 0;
		pClientGlobals->session_key_len = 0;

		// fix processes names
		strcpy(argv[0], "tcpServerChild");
		prctl(PR_SET_NAME, "tcpServerChild");

		// Get incoming buffer memory
		buf = (unsigned char *) mymalloc(MEMSIZE * sizeof(unsigned char));
		memset(buf, 0, MEMSIZE);

		// Get response memory
		response = (unsigned char *) mymalloc(MEMSIZE * sizeof(unsigned char));
		memset(response, 0, MEMSIZE);

		// Temp turn off keys 
		force_no_encryption();

		if (HANDSHAKWITHECLIENT())
		{
		    cout << "*** New connection from " << pClientGlobals->client_name << endl;
		    // Read client request and Write response to client
		    while (!quit && (rc = READ(pClientGlobals->my_private_rsa, cl, buf, MEMSIZE)) > 0)
		    {
			pClientGlobals->client_status = RUNNING_PROCESSING;

			pCommandChain = NULL;

			fflush(stdout);
			if (process_request(mypid, buf, cl, msgid, response, &response_len, &quit) != 0)
			{
			    if (!quit)
			    {
				//cout << "About to send : " << response << endl;
				wrc = WRITE(pClientGlobals->peer_public_rsa, cl, response, response_len);
				pClientGlobals->client_status = RUNNING_WAITING;
			    }
			}
			else
			{
			    cout << "Exiting ..";
			    quit = true;
			}

			// Clear out incoming and outgoing buffers
			memset(buf, 0, MEMSIZE);
			memset(response, 0, MEMSIZE);
			response_len = 0;

			pClientGlobals->session_rsa = (char *) mymalloc(KEY_SIZE);
			pClientGlobals->session_iv = (char *) mymalloc(BLOCK_SIZE);

			memset(pClientGlobals->session_rsa, 0, KEY_SIZE);
			memset(pClientGlobals->session_iv, 0, BLOCK_SIZE);

			make_session_keys(pClientGlobals->session_rsa, pClientGlobals->session_iv);

			// Temp turn off keys 
			force_no_encryption();
		    }
		}
		else
		{
		    cout << "Client Handshake failed\n";
		}

		// We are asked to quit, force shutdown of socket 
		shutdown(cl, SHUT_WR); /* inform remote that we are done */
		depleteSendBuffer(cl);
		close(cl);
		pClientGlobals->client_status = UNCONNECTED;

		cout << "Client disconnected cl = " << cl << endl;
		fflush(stdout);

		// Free Read and Write buffers
		if (buf)
		{
		    free(buf);
		    buf = NULL;
		}
		if (response)
		{
		    free(response);
		    response = NULL;
		}
	    }
	    catch (int e)
	    {
		cout << "\n****Exception " << e << endl;
		perror("Exception");
	    }

	    if (pClientGlobals)
	    {
		free(pClientGlobals);
		pClientGlobals = NULL;
	    }
	}
	else // Parent Process
	{
	    try
	    {
		cout << ".\n";
		// Create a monitor thread to exit this PID when Client dies
		pthread = pthread_create(&tid, NULL, &wait_on_client, &pid);
		if (pthread != 0)
		{
		    cout << "Failed to creat wait thread : " << strerror(pthread) << endl;
		    cout << "Exiting server!" << endl;
		    goto cleanup;
		}

		// Setup a new listener
		if (listen(fd, 5) == -1)
		{
		    perror("listen error");
		    exit(-1);
		}
		cout << "Listening ..";
	    }
	    catch (int e)
	    {
		cout << "***** parent exception \n";
	    }
	}
    }

cleanup:
    if (msgid > 0)
    {
	mq_close(msgid);
	mq_unlink("/msgname");
    }

    if (buf != NULL) free(buf);
    if (response != NULL) free(response);
    if (pClientGlobals->session_rsa != NULL) free(pClientGlobals->session_rsa);
    if (pClientGlobals->session_iv != NULL) free(pClientGlobals->session_iv);
    if (pClientGlobals != NULL) free(pClientGlobals);

    return 0;
}

int private_decrypt(RSA *rsa, unsigned char *enc_data, int data_len, unsigned char *decrypted)
{
    int result = -1;
    //cout << enc_data << endl;
    if (pClientGlobals->session_key == NULL || pClientGlobals->session_iv == NULL)
    {
	result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding1);
    }
    else
    {
	result = sym_decrypt(enc_data, data_len, pClientGlobals->session_rsa,
		pClientGlobals->session_iv, decrypted);
    }

    return result;
}

int private_encrypt(RSA *rsa, unsigned char * data, int data_len, unsigned char *encrypted)
{
    int result = -1;
    if (pClientGlobals->session_key == NULL || pClientGlobals->session_iv == NULL)
    {
	result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding1);
    }
    else
    {
	result = sym_encrypt(data, data_len, pClientGlobals->session_rsa,
		pClientGlobals->session_iv, encrypted);
    }

    return result;
}

int public_encrypt(RSA *rsa, unsigned char * data, int data_len, unsigned char *encrypted)
{
    int result = -1;
    if (pClientGlobals->session_key == NULL || pClientGlobals->session_iv == NULL)
    {
	result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding1);
    }
    else
    {
	result = sym_encrypt(data, data_len, pClientGlobals->session_rsa,
		pClientGlobals->session_iv, encrypted);
    }
    return result;
}

int public_decrypt(RSA *rsa, unsigned char * enc_data, int data_len, unsigned char *decrypted)
{
    int result = -1;
    if (pClientGlobals->session_key == NULL || pClientGlobals->session_iv == NULL)
    {
	result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding1);
    }
    else
    {
	result = sym_decrypt(enc_data, data_len, pClientGlobals->session_rsa,
		pClientGlobals->session_iv, decrypted);
    }
    return result;
}

void printLastError(char *msg)
{
    char * err = (char *) mymalloc(130);

    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

void handleErrors(void)
{
    fflush(stdout);

    printf("\n***ERROR***\n");
    ERR_print_errors_fp(stderr);
    printf("\n");
    exit(-1);
}

int sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
    //
    //    printf("sym key : ");
    //    hexdump(key,KEY_SIZE);
    //    printf("\niv : ");
    //    hexdump(iv,BLOCK_SIZE);;
    //    printf(">>>Encrypting Plan text from  : %s\n", plaintext);
    EVP_CIPHER_CTX *ctx;
    //cout << "<< INTO sym_encrypt()\n";

    //printf (">>>Encrypting Plan text from  : %s\n", plaintext);
    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
	printLastError("sym_encrypt()>EVP_CIPHER_CTX_new()");
	return -1;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
	printLastError("sym_encrypt()>EVP_EncryptInit_ex()");
	return -1;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
	printLastError("sym_encrypt()>EVP_EncryptUpdate()");
	return -1;
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
	printLastError("sym_encrypt()>EVP_EncryptFinal_ex()");
	return -1;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    //cout << ">> OUT OF sym_encrypt()\n";
    return ciphertext_len;
}

int sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
    //
    //    printf("sym key : ");
    //    hexdump(key,KEY_SIZE);
    //    printf("\niv : ");
    //    hexdump(iv,BLOCK_SIZE);;
    //	    
    //cout << "<< INTO sym_decrypt()\n";
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
	printLastError("sym_decrypt()>EVP_CIPHER_CTX_new()");
	return -1;
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
	printLastError("sym_decrypt()>EVP_DecryptInit_ex()");
	return -1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
	printLastError("sym_decrypt()>EVP_DecryptUpdate()");
	return -1;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
	printLastError("sym_decrypt()>EVP_DecryptFinal_ex()");
	return -1;
    }
    plaintext_len += len;

    plaintext[plaintext_len] = '\0';

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //printf(">>>decrypted to Plan text : %s\n", plaintext);

    //cout << ">> OUT OF sym_decrypt()\n";
    return plaintext_len;
}

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char *encrypted_key;
    int encrypted_key_len;
    unsigned char *iv;
    EVP_PKEY *pkey = EVP_PKEY_new();
    int ciphertext_len;

    if (!EVP_PKEY_assign_RSA(pkey, pClientGlobals->my_private_rsa))
	handleErrors();

    int len;

    encrypted_key = (unsigned char *) mymalloc(EVP_PKEY_size(pkey));
    iv = mymalloc(EVP_MAX_IV_LENGTH);


    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the envelope seal operation. This operation generates
     * a key for the provided cipher, and then encrypts that key a number
     * of times (one for each public key provided in the pub_key array). In
     * this example the array size is just one. This operation also
     * generates an IV and places it in iv. */
    if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key,
	    &encrypted_key_len, iv, &pkey, 1))
	handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_SealUpdate can be called multiple times if necessary
     */
    if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    unsigned char *encrypted_key;
    int encrypted_key_len;
    unsigned char *iv;
    EVP_PKEY *pkey = EVP_PKEY_new();

    if (!EVP_PKEY_assign_RSA(pkey, pClientGlobals->my_private_rsa))
	handleErrors();

    int len;

    int plaintext_len;

    encrypted_key = mymalloc(EVP_PKEY_size(pkey));
    iv = mymalloc(EVP_MAX_IV_LENGTH);
    encrypted_key_len = EVP_PKEY_size(pkey);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. The asymmetric private key is
     * provided and priv_key, whilst the encrypted session key is held in
     * encrypted_key */
    if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
	    encrypted_key_len, iv, pkey))
	handleErrors();
    //int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    //                 const unsigned char *ek, int ekl, const unsigned char *iv,
    //                 EVP_PKEY *priv);
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_OpenUpdate can be called multiple times if necessary
     */
    if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	handleErrors();

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int noenc_read(int desc, unsigned char *buffer, int buffer_size, int flag)
{
    struct timeval t;
    t.tv_sec = 2;
    t.tv_usec = 0;
    int rc = 0;
    int received = 0;

    uint32_t l;
    //
    rc = recv(desc, &l, 4, 0);
    unsigned long ul = ntohl(l);
    //
    //    cout << "Incoming size (" << rc << " bytes)= " << ul << " ("<< l << ")" << endl;
    //    
    //sleep(20);
    try
    {
	//	cout << "Receiving ..";
	do
	{
	    rc = recv(desc, &buffer[received], ul - received, flag);
	    if (rc == 0)
		return -1;
	    received += rc;
	}
	while (received < ul);
	//	cout << received << " bytes\n";
    }

    catch (const std::runtime_error& re)
    {
	// speciffic handling for runtime_error
	std::cerr << "Runtime error: " << re.what() << std::endl;
    }
    catch (const std::exception& ex)
    {
	// speciffic handling for all exceptions extending std::exception, except
	// std::runtime_error which is handled explicitly
	std::cerr << "Error occurred: " << ex.what() << std::endl;
    }
    catch (...)
    {
	// catch any other errors (that we have no information about)
	std::cerr << "Unknown failure occurred. Possible memory corruption" << std::endl;
    }
    return rc;
}

int noenc_write(int desc, unsigned char * buffer, int buffer_len, int flag)
{
    int sent = 0;

    uint32_t l = htonl(buffer_len);

    send(desc, &l, 4, 0);
    //    cout << "Out going size = " << buffer_len << endl;    
    //sleep(20);

    //cout << "Sending ...";
    sent = send(desc, buffer, buffer_len, flag);
    //cout << sent << " bytes\n";
    return sent;
}

int FIRST_READ(int desc, unsigned char *buffer, int buffer_size)
{

    return READ(NULL, desc, buffer, buffer_size);
}

int READ(RSA *rsa, int desc, unsigned char *buffer, int buffer_size)
{
    int received = 0;

    rsa ? received = enc_read(rsa, desc, buffer, buffer_size, 0) : received = noenc_read(desc, buffer, buffer_size, 0);

    fflush(stdout);
    return received;
}

int identify_protocol(std::string sbuf)
{
    int protocol = 0;
    // ******************************************************
    // Identify protocol 
    if (sbuf.compare(0, 14, "GET / HTTP/1.1") == 0)
    {
	protocol = HTTP_PROTO; // HTTP protocol
    }
    else if (sbuf.compare(0, 3, "SSH") == 0)
    {
	protocol = SSH_PROTO; // SSH            
    }
    else
    {
	protocol = NATIVE_PROTO;
    }
    return protocol;
}

void freeCommandData(pcmd_data d)
{
    if (d == NULL)
    {
	return;
    }
    else if (d->next == NULL)
    {
	free(d);
	d = NULL;
	return;
    }
    else
    {
	freeCommandData(d->next);
	free(d);
	d = NULL;
	return;
    }
}

void freeCommandChain(pcmd c)
{
    if (c == NULL)
	return;

    if (c->next == NULL)
    {
	freeCommandData(c->pdata);
	free(c);
	c = NULL;
	return;
    }
    else
    {
	freeCommandChain(c->next);
	freeCommandData(c->pdata);
	free(c);
	c = NULL;
	return;
    }
}

void dump_data(pcmd_data d)
{
    while (d)
    {
	d = d->next;
    }
}

void dump_command(pcmd c)
{
    while (c)
    {
	dump_data(c->pdata);
	c = c->next;
    }
}

int parse_commands(json a, int inc, pcmd prev_cmd)
{
    char cinc[10];

    try
    {
	sprintf(cinc, "%d\0", inc);
	if (a.find(cinc) == a.end())
	{
	    return 0;
	}
	else
	{
	    string c;
	    if (!a.at(cinc).is_object())
	    {
		return -1;
	    }
	    if (a.at(cinc).find("command") == a.at(cinc).end())
	    {
		return -1;
	    }

	    c.assign(a.at(cinc).find("command").value());

	    pcmd pc = new_command();
	    if (prev_cmd) prev_cmd->next = pc;
	    strcpy(pc->cmd, c.c_str());
	    json jnul = nullptr;
	    json v = (a.at(cinc).find("data") != a.at(cinc).end()) ? a.at(cinc).find("data").value() : jnul;

	    if (pCommandChain == NULL)
		pCommandChain = pc;

	    pcmd_data pcmd_d = NULL;
	    pcmd_data prev_d = NULL;
	    if (v.is_object())
	    {
		json::iterator i(&v);
		i = v.begin();
		while (i != v.end())
		{
		    pcmd_d = new_command_data();
		    //cout << "Parameter[" << i.key() << "] = " << i.value() << endl;
		    string dp;
		    dp.assign(string(i.key()));
		    strcpy(pcmd_d->parm_name, dp.c_str());
		    string dv;
		    if (i.value().is_string())
			dv.assign(i.value());
		    else
			dv.assign(i.value().dump());

		    strcpy(pcmd_d->parm_value, dv.c_str());
		    if (prev_d != NULL)
			prev_d->next = pcmd_d;
		    else
			pc->pdata = pcmd_d;

		    prev_d = pcmd_d;
		    i++;
		}
	    }
	    else
	    {
		if (prev_d != NULL)
		    prev_d->next = pcmd_d;
	    }

	    return parse_commands(a, inc + 1, pc);
	}
    }
    catch (const std::invalid_argument&)
    {
	printf("%s json parsing error. \n", __FUNCTION__);
	return -1;
    }

}

bool sys_call(pcmd c, char *response, int *response_len)
{
    if (!c) return false;

    typedef std::vector<std::string> OptionsType;
    OptionsType options;
    string scmd;
    scmd.assign(c->cmd);
    char *argv[255];
    int argc = 0;

    // Authenticate command
    if (scmd.compare("system") == 0)
    {
	string sys_call;
	string sys_call_options;

	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string(d->parm_name);
		if (parm.compare("sys_call") == 0)
		{
		    sys_call.assign(d->parm_value);
		}

		if (parm.compare("options") == 0)
		{
		    sys_call_options.assign(d->parm_value);

		    boost::split(options, sys_call_options, boost::is_any_of(" "));
		    argc = options.size();
		    for (int i = 0; i < argc; i++)
		    {
			argv[i] = &options[i][0];
			//std::strcpy(argv[i], options[i].c_str());			
		    }
		}
	    }
	    d = d->next;
	}

	//cout << "Received 1 : " << response << endl;
	string cmd;
	cmd = sys_call; // + string(" ") + sys_call_options;
	string str_response2 = exec(cmd.c_str(), argc, argv);

	str_response2 = trim(str_response2);
	string str_response1 = string("{\"1\":{\"response\":\"sys_call_response\",\"data\":{\"error\": 0,\"message\":\"") +
		string("prep to receive") + string("\"}}}");
	str_response1 = trim(str_response1);
	*response_len = str_response1.length();
	strncpy(response, str_response1.c_str(), str_response1.length());

	//cout << "Sending back 1 : " << str_response1 << endl;
	int n = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, str_response1.c_str(), *response_len);
	if (n < 0)
	{
	    perror("Write");
	    return true;
	}

	n = READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, response, MEMSIZE);
	//cout << "Received 2 : " << response << endl;
	if (n > 0 && (strncmp(response, "OK", 2) == 0))
	{
	    *response_len = str_response2.length();

	    //cout << "Sending back 2 : " << str_response2 << endl;
	    n = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock,
		    str_response2.c_str(), *response_len);
	    if (n < 0)
	    {
		perror("Write");
	    }
	}
	// prevent automatic send 'OK' after return
	memset(response, 0, MEMSIZE);
	*response_len = 0;
	return true;
    }
    else
    {
	return false;
    }
}

bool authenticate(pcmd c, char *response, int *response_len)
{
    if (!c) return false;

    string scmd;
    scmd.assign(c->cmd);

    // Authenticate command
    if (scmd.compare("authenticate") == 0)
    {
	string userid;
	string password;

	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string(d->parm_name);
		if (parm.compare("userid") == 0)
		{
		    userid.assign(d->parm_value);
		}

		if (parm.compare("password") == 0)
		{
		    password.assign(d->parm_value);
		}
	    }
	    d = d->next;
	}

	cout << "userid : " << userid << " password : " << password << endl;
	strcpy(response, "{\"1\":{\"response\":\"error\",\"data\":{\"error\": 0,\"message\":\"none\"}}}\0");
	*response_len = strlen(response);

	return true;
    }
    else
    {
	return false;
    }
}

int set_session_key(unsigned char * genrated_key, int *genkey_len)
{
    // generate rundom number
    memset(genrated_key, 0, RANDOMKEY_SIZE);
    RAND_bytes(genrated_key, RANDOMKEY_SIZE);
    *genkey_len = RANDOMKEY_SIZE;

    pClientGlobals->session_key = genrated_key;
    pClientGlobals->session_key_len = *genkey_len;

}

int make_session_keys(unsigned char *key, unsigned char *iv)
{

    // Load the necessary cipher
    EVP_add_cipher(EVP_aes_256_cbc());
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-256-cbc");

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    const EVP_MD *dgst = NULL;
    const unsigned char *salt = NULL;

    OpenSSL_add_all_digests();
    dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
	fprintf(stderr, "EVP_get_digestbyname() error: no such digest\n");
	return 1;
    }

    if (!EVP_BytesToKey(cipher, dgst, salt,
	    (unsigned char *) pClientGlobals->session_key,
	    pClientGlobals->session_key_len, 1, key, iv))
    {
	fprintf(stderr, "EVP_BytesToKey failed\n");
	return 1;
    }

    return 0;
}

bool get_session_key(char *response, int * response_len)
{
    if (pClientGlobals->session_key)
	return false;

    int genkeylen = 0;

    char *genkey = (char *) mymalloc(RANDOMKEY_SIZE);
    memset(genkey, 0, RANDOMKEY_SIZE);

    set_session_key(genkey, &genkeylen);

    memcpy(response, genkey, genkeylen);
    *response_len = genkeylen;
    return true;
}

bool sendkeys(pcmd c, char *response)
{
    string scmd;
    string parm1;
    scmd.assign(c->cmd);
    char genkey = NULL;
    int genkey_len = 0;

    if (scmd.compare("getkeys") == 0)
    {
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string(d->parm_name);
		if (parm.compare("parm") == 0)
		{
		    parm1.assign(d->parm_value);
		}
	    }
	    d = d->next;
	}

	get_session_key(genkey, &genkey_len);
    }
    else
    {
	return false;
    }
}

bool handshake(pcmd c, char *response, int *response_len)
{
    if (pClientGlobals->client_status != HANDSHAKE)
	return false;

    string scmd;

    string client_public_key_prep;
    scmd.assign(c->cmd);
    strcpy(pClientGlobals->client_name, "UNKNOWN");
    *response_len = 0;

    if (scmd.compare("handshake") == 0)
    {
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string(d->parm_name);
		if (parm.compare("Iam") == 0)
		{
		    if (strlen(d->parm_value) <= NAME_SIZE)
			strcpy(pClientGlobals->client_name, d->parm_value);
		    else
			strncpy(pClientGlobals->client_name, d->parm_value, NAME_SIZE);
		}
		else if (parm.compare("clientkey") == 0)
		{
		    client_public_key_prep.assign(d->parm_value);
		}
	    }
	    d = d->next;
	}
	if ((strcmp(pClientGlobals->client_name, "UNKNOWN") == 0) && (client_public_key_prep.compare("prep2recv") != 0))
	{
	    strcpy(response, "{\"1\":{\"response\":\"error\",\"data\":{\"error\":-1,\"message\":\"rejected client\"}}}\0");
	    *response_len = strlen(response);
	}
	else
	{
	    strcpy(response, "OK");
	    *response_len = strlen(response);
	    // send unencrypted 
	    int rc = WRITE(NULL, pClientGlobals->client_sock, response, *response_len);
	    if (rc > 0)
	    {
		// receive unencrypted
		rc = READ(NULL, pClientGlobals->client_sock,
			response, *response_len);
		if (rc < 0)
		    return false;

		// We have the Client's public key. From now on we encrypt SEND with peer's public key		
		pClientGlobals->peer_public_key_len = rc;
		if ((pClientGlobals->peer_public_key_string =
			(unsigned char *) mymalloc(sizeof(unsigned char) * pClientGlobals->peer_public_key_len))
			!= NULL)
		{
		    strncpy(pClientGlobals->peer_public_key_string, response,
			    pClientGlobals->peer_public_key_len);

		    //init_openssl();
		    BIO *ppub = BIO_new_mem_buf(pClientGlobals->peer_public_key_string, -1);
		    EVP_PKEY *peer_EVP_key = PEM_read_bio_PUBKEY(ppub, NULL, NULL, NULL);
		    pClientGlobals->peer_public_rsa = EVP_PKEY_get1_RSA(peer_EVP_key);
		    cleanup_openssl();
		    // From now on, we encrypt comm to peer with its public key
		}
		else
		    return false;

		send_my_pubkey();

		strcpy(response, "OK");
		*response_len = strlen(response);

		pClientGlobals->session_key = NULL;
		pClientGlobals->session_iv = NULL;
		pClientGlobals->session_rsa = NULL;
		pClientGlobals->session_key_len = 0;
	    }
	    else return false;
	}
    }
    else
    {

	return false;
    }
    return true;
}

inline bool filestat(const std::string& name, struct stat *pstatbuf, char * _filemode)
{
    char *filemode = "";
    bool exists = ((pstatbuf = stat(name.c_str(), pstatbuf)) == 0);
    if (!exists)
	return false;

    //    filemode[0] = ( (pstatbuf->st_mode & S_IRUSR) ? "r" : "-");
    //    filemode[1] =( (pstatbuf->st_mode & S_IWUSR) ? "w" : "-");
    //    filemode[2] =( (pstatbuf->st_mode & S_IXUSR) ? "x" : "-");
    //    filemode[3] =( (pstatbuf->st_mode & S_IRGRP) ? "r" : "-");
    //    filemode[4] =( (pstatbuf->st_mode & S_IWGRP) ? "w" : "-");
    //    filemode[5] =( (pstatbuf->st_mode & S_IXGRP) ? "x" : "-");
    //    filemode[6] =( (pstatbuf->st_mode & S_IROTH) ? "r" : "-");
    //    filemode[7] =( (pstatbuf->st_mode & S_IWOTH) ? "w" : "-");
    //    filemode[8] =( (pstatbuf->st_mode & S_IXOTH) ? "x" : "-");
    strcpy(_filemode, filemode);

    return true;
}

int send_my_pubkey()
{
    char *send_buffer = (char*) mymalloc(sizeof(char)*MAX_UNENCRYPTED_TEXT_SIZE);
    char *receive_bffer = (char *) mymalloc(sizeof(char)*MAX_UNENCRYPTED_TEXT_SIZE);
    memset(send_buffer, 0, MAX_UNENCRYPTED_TEXT_SIZE);

    int ret = 0;

    char *servername = "qantv101";
    // build prepare-to-receive json request
    string prep2rec = string("{\"1\":{\"response\":\"mypubkey\"") +
	    string(",\"data\":") +
	    string("{\"servername\":\"") + string(servername) + string("\"") +
	    string(",\"filename\":\"publickey.pem\"") +
	    string(",\"filesize\":") + to_string(pClientGlobals->mypublic_key_len) +
	    string(",\"options\":\"0000000000\"") +
	    string("}}}");

    // send prepare-to-receive json request
    int rc = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, prep2rec.c_str(), prep2rec.length());

    // Receive unencrypted
    rc = READ(NULL, pClientGlobals->client_sock, receive_bffer, MAX_UNENCRYPTED_TEXT_SIZE);

    WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, pClientGlobals->mypublic_key_string, pClientGlobals->mypublic_key_len);

    free(send_buffer);
    free(receive_bffer);
    // cout << "Done sending!! Total sent = " << total_sent << endl;
    ret = 0;
    return ret;
}

int send_my_pubkey_from_file()
{
    // cout << "<< IN send_my_pubkey()\n";
    int ret = 0;
    struct stat filestatbuf;
    int send_buff_limit = MAX_UNENCRYPTED_TEXT_SIZE;
    int bytes_sent = 0, total_sent = 0;
    string filepath;
    char filemode[10];

    filepath = ".ssh/public.pem";
    if (filestat(filepath, &filestatbuf, filemode))
    {
	// open file and seek top
	int fp = open(filepath.c_str(), O_RDONLY);
	lseek(fp, 0, SEEK_SET);

	int receive_bffer_size = MAX_UNENCRYPTED_TEXT_SIZE;
	int bytes_read = 0;
	unsigned long filesize = filestatbuf.st_size;
	char *send_buffer = (char*) mymalloc(sizeof(char)*send_buff_limit);
	char *receive_bffer = (char *) mymalloc(sizeof(char)*receive_bffer_size);
	memset(send_buffer, 0, send_buff_limit);

	char *servername = "qantv101";
	// build prepare-to-receive json request
	string prep2rec = string("{\"1\":{\"response\":\"mypubkey\"") +
		string(",\"data\":") +
		string("{\"servername\":\"") + string(servername) + string("\"") +
		string(",\"filename\":\"publickey.pem\"") +
		string(",\"filesize\":") + to_string(filesize) +
		string(",\"options\":\"0000000000\"") +
		string("}}}");

	//cout << "Sending back : " << prep2rec << endl;

	// send prepare-to-receive json request
	int rc = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, prep2rec.c_str(), prep2rec.length());
	//cout << "WRITE() returned : " << rc << endl;

	// wait-receive acknowledgemnt/go ahead from client
	rc = READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, receive_bffer, receive_bffer_size);

	// Loop until all file is sent
	while ((bytes_read = read(fp, send_buffer, send_buff_limit)) != 0)
	{
	    bytes_sent = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, send_buffer, bytes_read);

	    total_sent += bytes_sent;

	    // wait-receive acknowledgement from client 
	    rc = READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, receive_bffer, receive_bffer_size);
	}

	free(send_buffer);
	free(receive_bffer);
	// cout << "Done sending!! Total sent = " << total_sent << endl;
	ret = 0;
    }
    else
    {

	cout << "file " << filepath << " does not exist" << endl;
	ret = -1;
    }
    return ret;
}

int send_file(char *directory, char *filename)
{
    // cout << "<< IN send_file()\n";
    int ret = 0;
    struct stat filestatbuf;
    int send_buff_limit = MAX_UNENCRYPTED_TEXT_SIZE;
    int bytes_sent = 0, total_sent = 0;
    string filepath;
    char filemode[10];

    filepath = string(directory) + "/" + string(filename);
    if (filestat(filepath, &filestatbuf, filemode))
    {
	try
	{
	    // open file and seek top
	    FILE *fp = fopen(filepath.c_str(), "r+");
	    fseek(fp, 0, SEEK_SET);

	    int receive_bffer_size = MAX_UNENCRYPTED_TEXT_SIZE;
	    int bytes_read = 0;
	    unsigned long filesize = filestatbuf.st_size;
	    unsigned char *send_buffer = (unsigned char*) mymalloc(sizeof(unsigned char)*send_buff_limit);
	    unsigned char *receive_bffer = (unsigned char *) mymalloc(sizeof(unsigned char)*receive_bffer_size);
	    memset(send_buffer, 0, send_buff_limit);
	    memset(receive_bffer, 0, receive_bffer_size);

	    // build prepare-to-receive json request
	    string prep2rec = "{\"1\":{\"response\":\"prep2rcvfile\",\"data\":{\"filename\":\"" + string(filename) + "\", \"filesize\":" + to_string(filesize) + "}}}";
	    //cout << "Sending back : " << prep2rec << endl;

	    // send prepare-to-receive json request
	    int rc = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, prep2rec.c_str(), prep2rec.length());
	    //cout << "WRITE() returned : " << rc << endl;

	    // wait-receive acknowledgemnt/go ahead from client
	    rc = READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, receive_bffer, receive_bffer_size);

	    // enc test

	    //	    char *encrypted_buff = mymalloc(send_buff_limit * sizeof(char)); 
	    //	    char *decrypted_buff = mymalloc(send_buff_limit * sizeof(char)); 
	    //	    FILE * tfp = fopen("mytest.out", "w+");
	    //	    
	    // end enc test
	    bDumpFile = true;
	    // Loop until all file is sent
	    while ((bytes_read = fread(send_buffer, 1, send_buff_limit, fp)) != 0)
	    {
		// enc test	     

		//int sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
		//	    unsigned char *iv, unsigned char *ciphertext)
		//	    
		//	    int bcount = sym_encrypt(send_buffer, bytes_read, pClientGlobals->session_rsa, 
		//		    pClientGlobals->session_iv,encrypted_buff );


		//int sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
		// unsigned char *iv, unsigned char *plaintext)
		//	    bcount = sym_decrypt(encrypted_buff, bcount,pClientGlobals->session_rsa, 
		//		    pClientGlobals->session_iv,  decrypted_buff);
		//	    
		//	    if(memcmp(send_buffer,decrypted_buff,bytes_read) == 0)
		//	    {
		//		cout << "enc-dec success \n";
		//	    }
		//	    else
		//	    {
		//		cout << "***************************enc-dec FAILED \n";
		//		exit(-1);
		//	    }
		//	    
		//	    fwrite(decrypted_buff, 1, bytes_read,  tfp);
		// end enc test
		//hexdump(send_buffer, bytes_read);
		bytes_sent = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, send_buffer, bytes_read);

		total_sent += bytes_sent;

		// wait-receive acknowledgement from client 
		rc = READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, receive_bffer, receive_bffer_size);
	    }
	    bDumpFile = false;
	    // enc test
	    //	    fclose(tfp);
	    // enc end
	    cout << "Done sending!! Total sent = " << total_sent << endl;
	    free(send_buffer);
	    free(receive_bffer);
	    ret = 0;
	}

	catch (const std::runtime_error& re)
	{
	    // speciffic handling for runtime_error
	    std::cerr << "Runtime error: " << re.what() << std::endl;
	}
	catch (const std::exception& ex)
	{
	    // speciffic handling for all exceptions extending std::exception, except
	    // std::runtime_error which is handled explicitly
	    std::cerr << "Error occurred: " << ex.what() << std::endl;
	}
	catch (...)
	{
	    // catch any other errors (that we have no information about)
	    std::cerr << "Unknown failure occurred. Possible memory corruption" << std::endl;
	}
    }
    else
    {
	cout << "file " << filepath << " does not exist" << endl;
	ret = -1;
    }
    return ret;
}

bool receive_file(pcmd c, unsigned char *response, unsigned char *savedirectory, unsigned char *savefilename)
{
    string scmd;
    scmd.assign(c->cmd);

    int bufsize = MEMSIZE;
    unsigned char *buffer = (unsigned char*) malloc(sizeof(unsigned char) * bufsize);
    long filesize = 0;
    memset(buffer, 0, bufsize);
    char mysavefilename[100];

    int n = 0;
    int total_bytes_received = 0;
    bool rc = true;

    //    auto begin = chrono::high_resolution_clock::now ( );

    if (scmd.compare("prep2rcvfile") == 0)
    {
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string(d->parm_name);
		if (parm.compare("filename") == 0)
		{
		    //cout << "got Filename : " << d->parm_value << endl;
		}
		if (parm.compare("filesize") == 0)
		{
		    //cout << "got filesize : " << d->parm_value << endl;
		    filesize = atol(d->parm_value);
		}
	    }

	    d = d->next;
	}

	if (savefilename == NULL)
	{
	    strcpy(mysavefilename, d->parm_value);
	}
	else
	{
	    strcpy(mysavefilename, savefilename);
	}

	boost::filesystem::path p(mysavefilename);
	string indirectory = p.parent_path().string();
	string filename_only = p.filename().string();

	indirectory.assign(pClientGlobals->client_name);
	string fulldir = makedirectory(string((char *) savedirectory), indirectory);

	if (fulldir.empty())
	{
	    cout << "Unable to create directory '" << savedirectory << "/" << indirectory << "'" << endl;
	    return false;
	}

	string filepath = fulldir + "/" + filename_only;

	FILE* infile = fopen(filepath.c_str(), "w+");
	if (infile == NULL)
	{
	    unsigned char error[100];
	    sprintf(error, "File open error '%s'", filepath.c_str());
	    perror(error);
	    return false;
	}

	strcpy(response, "OK\0");

	n = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, response, strlen(response));

	if (n < 0)
	{
	    perror("ERROR writing to socket");
	    return false;
	}
	bzero(buffer, bufsize);
	while ((total_bytes_received < filesize) &&
		((n = READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, buffer, bufsize)) > 0))
	{
	    if (n < 0)
	    {
		perror("ERROR reading from socket");
		return false;
	    }

	    fwrite(buffer, 1, n, infile);

	    buffer[n] = '\0';
	    //cout << buffer;
	    total_bytes_received += n;

	    // show bytes received on terminal
	    //	    printf ( "\33[2K\r" );
	    //	    printf ( "Received %d out of %d" , total_bytes_received , filesize );
	    //	    fflush ( stdout );

	    strcpy(response, "OK\0");
	    n = WRITE(pClientGlobals->peer_public_rsa, pClientGlobals->client_sock, response, strlen(response));
	    bzero(buffer, bufsize);
	}
	fclose(infile);

	//	printf ( "\nTotal bytes received from server (%d bytes) \n" , total_bytes_received );
	READ(pClientGlobals->my_private_rsa, pClientGlobals->client_sock, buffer, bufsize);
	if (strncmp(buffer, "OK", 2) == 0)
	{
	    rc = true;
	}
	else
	{
	    rc = false;
	}

	//	auto end = chrono::high_resolution_clock::now ( );
	//	auto dur = end - begin;
	//
	//	double total_time = std::chrono::duration_cast<std::chrono::milliseconds>( dur ).count ( );
	//	cout << "Time elapsed : " << total_time / 1000.0 << " seconds\n";


    }
    else
    {
	if (scmd.compare("error") == 0)
	{
	    pcmd_data d = c->pdata;
	    while (d)
	    {
		if (d->parm_name != NULL)
		{
		    string parm = string(d->parm_name);
		    if (parm.compare("error") == 0)
		    {
			cout << "Error : " << d->parm_value << endl;
		    }
		    if (parm.compare("message") == 0)
		    {
			cout << "Message : " << d->parm_value << endl;
		    }
		}
		d = d->next;
	    }
	}

	memset(response, 0, MEMSIZE);
	rc = false;
    }

    free(buffer);
    return rc;

}

bool get_file(pcmd c, char *response, int *response_len)
{
    if (!c) return false;
    string scmd;
    scmd.assign(c->cmd);
    char cwd[PATH_MAX];
    *response_len = 0;

    if (scmd.compare("getfile") == 0)
    {
	string filename;
	string options;

	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string(d->parm_name);
		if (parm.compare("filename") == 0)
		{
		    filename.assign(d->parm_value);
		    //		    cout << "File name string : " << filename << endl;
		}

		if (parm.compare("options") == 0)
		{
		    options.assign(d->parm_value);
		}
	    }
	    d = d->next;
	}

	getcwd(cwd, sizeof(cwd));
	if (send_file(cwd, filename.c_str()) < 0)
	{
	    strcpy(response, "{\"1\":{\"response\":\"error\",\"data\":{\"error\": -1,\"message\":\"failed to send file\"}}}\0");
	    *response_len = strlen(response);
	}

	return true;
    }
    else
    {

	return false;
    }

}

bool command_not_found(pcmd c, char *response, int *response_len)
{
    *response_len = 0;
    string scmd;
    scmd.assign(c->cmd);
    cout << "Command not supported : " << scmd << " data [ ";
    pcmd_data d = c->pdata;
    while (d)
    {
	if (d->parm_name != NULL) cout << " [ " << d->parm_name << " = ";
	if (d->parm_value != NULL) cout << d->parm_value << " ] ";
	d = d->next;
    }
    cout << endl;

    strcpy(response, "{\"rc\":-1,\"msg\":\"json parsing error. malformed request\"}");
    //strcpy(response, "{\"1\":{\"response\":\"error\",\"data\":{\"error\": -1,\"message\":\"malformed request\"}}}\0");

    *response_len = strlen(response);

    return true;
}

int exec_commands(char *response, int *response_len)
{
    if (pCommandChain == NULL)
	return -1;

    pcmd c = pCommandChain;
    while (c != NULL && c->cmd != NULL)
    {
	if (handshake(c, response, response_len))goto NEXTCOMMAND;
	if (get_session_key(response, response_len)) goto NEXTCOMMAND;
	if (sys_call(c, response, response_len)) goto NEXTCOMMAND;
	if (authenticate(c, response, response_len)) goto NEXTCOMMAND;
	if (get_file(c, response, response_len)) goto NEXTCOMMAND;

	else command_not_found(c, response, response_len);

NEXTCOMMAND:
	c = c->next;
    }
    //cout << "exe_ response : " << response << endl;
    return 1;
}

int process_request(int pid, unsigned char *input, int cl_sock,
	mqd_t msgid, unsigned char * response, int *response_len, bool *quit_on_return)
{
    std::string sbuf((char *) input);
    typedef boost::tokenizer<boost::char_separator<char> > tokenizer;

    boost::char_separator<char> sep(";");
    // Start tokenizing
    tokenizer tokens(sbuf, sep);
    tokenizer::iterator token = tokens.begin();
    bool parseError;
    int rc_resp;
    int protocol = NATIVE_PROTO;
    int ret = 1;
    unsigned char *msg = NULL;
    *quit_on_return = false;
    *response_len = 0;
    if (!input) // empty input, exit
	goto cleanup;

    // cout << input << endl;

    rc_resp = 0;

    // Create message buffer for local Servent client
    msg = (char*) mymalloc(1024);
    if (!msg)
    {
	perror("msg");
	goto cleanup;
    }

    // ******************************************************
    // Identify protocol 
    protocol = identify_protocol(sbuf);

    // *******************************************************

    parseError = false;
    switch (protocol)
    {
	case NATIVE_PROTO:
	    try
	    {
		pCommandChain = NULL;
		json jinput;
		try
		{
		    jinput = json::parse(input);
		}
		catch (const std::invalid_argument&)
		{
		    cout << "json exception parse failed" << endl;
		    parseError = true;
		}

		if (parse_commands(jinput, 1, NULL) != -1)
		{
		    parseError = exec_commands(response, response_len) == -1;
		    dump_command(pCommandChain);
		}
		else
		{
		    cout << "parse_command() failed" << endl;
		    parseError = true;
		}
		freeCommandChain(pCommandChain);
	    }
	    catch (const std::invalid_argument&)
	    {
		parseError = true;
	    }
	    fflush(stdout);

	    if (!strlen(response) && parseError)
	    {
		//strcpy(response, "{\"rc\":-1,\"msg\":\"json parsing error. malformed request\"}");
		strcpy(response, "{\"1\":{\"response\":\"error\",\"data\":{\"error\": -1,\"message\":\"malformed request\"}}}\0");
		*response_len = strlen(response);
		printf("json parsing error. \n");
	    }

	    // Process tokenized buffer
	    //send_message_queue(msgid, input);

	    // force a response if empty
	    if (*response_len == 0)
	    {
		strcpy(response, "OK\0");
		*response_len = strlen(response);
	    }
	    break;
	case HTTP_PROTO:
	    serve_file(cl_sock, "index.html");
	    *quit_on_return = true; // Tell caller not to wait for response
	    break;
	case SSH_PROTO:
	    sprintf(response, "%s", "OK\0");
	    *response_len = strlen(response);
	    break;
	default:
	    break;
    }

    // ****************** Clean up and exit ********************************
cleanup:
    if (msg)
    {
	free(msg);
	msg = NULL;
    }

    return ret;
}

int wait_on_server(int *pid)
{
    int status;
    waitpid(*pid, &status, 0);
    printf("Ending client service process \n");
    fflush(stdout);

    return 0;
}

int wait_on_client(int *pid)
{
    int status;

    waitpid(*pid, &status, 0);
    //wait(&status);
    printf("*** Client %d connection CLOSED! ***\n", *pid);
    fflush(stdout);

    return 0;
}

int get_new_socket2()
{
    int sockfd = 0;
    int port = atoi(SERVERPORT);
    struct sockaddr_in name;
    int yes = 1;

    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
	perror("server: socket");
	exit(-1);
    }
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
	    sizeof(int)) == -1)
    {
	perror("setsockopt SO_REUSEADDR");
	exit(1);
    }

    if (bind(sockfd, (struct sockaddr *) &name, sizeof(name)) < 0)
    {
	perror("server: bind");
	exit(-1);
    }
    if (port == 0) /* if dynamically allocating a port */
    {
	int namelen = sizeof(name);
	if (getsockname(sockfd, (struct sockaddr *) &name, &namelen) == -1)
	{

	    perror("server: getsockname");
	    exit(-1);
	}
	port = ntohs(name.sin_port);
    }

    return(sockfd);
}

int get_new_socket3(char *portno)
{
    int sockfd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, portno, &hints, &servinfo)) != 0)
    {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
	if ((sockfd = socket(p->ai_family, p->ai_socktype,
		p->ai_protocol)) == -1)
	{
	    perror("server: socket");
	    continue;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
		sizeof(int)) == -1)
	{
	    perror("setsockopt SO_REUSEADDR");
	    exit(1);
	}

	//        if (setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO, &t,sizeof(t)) == -1)
	//        {            
	//            perror("setsockopt SO_RCVTIMEO");
	//            exit(1);
	//        }

	if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
	{
	    close(sockfd);
	    perror("server: bind");
	    continue;
	}

	break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
	fprintf(stderr, "server: failed to bind\n");
	exit(1);
    }

    return sockfd;
}

int get_new_socketIPC(char *socket_path)
{
    int fd;
    struct sockaddr_un addr;
    int istrue = 1;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
	perror("socket error");
	exit(-1);
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &istrue, sizeof(int));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*socket_path == '\0')
    {
	*addr.sun_path = '\0';
	strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
    }
    else
    {
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	unlink(socket_path);
    }

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
    {
	perror("** bind error **");
	exit(-1);
    }

    return fd;

}

int set_encsend_buffer_size()
{
    if (pClientGlobals->my_private_rsa && pClientGlobals->session_iv && pClientGlobals->session_rsa)
    {
	return MAX_UNENCRYPTED_TEXT_SIZE;
    }
    else if (pClientGlobals->my_private_rsa && pClientGlobals->session_iv == NULL && pClientGlobals->session_rsa == NULL)
    {

	return 180;
    }
    return MAX_UNENCRYPTED_TEXT_SIZE;
}

int set_encrecv_buffer_size()
{
    if (pClientGlobals->my_private_rsa && pClientGlobals->session_iv && pClientGlobals->session_rsa)
    {
	return MAX_UNENCRYPTED_TEXT_SIZE;
    }
    else if (pClientGlobals->my_private_rsa && pClientGlobals->session_iv == NULL && pClientGlobals->session_rsa == NULL)
    {

	return 1024;
    }
    return MAX_UNENCRYPTED_TEXT_SIZE;
}

int enc_read(RSA *rsa, int desc, unsigned char *buffer, int buffer_size, int flag)
{
    int rcv_parts = 0;
    bool quit = false;
    unsigned char *encrypted = mymalloc(MEMSIZE * sizeof(unsigned char));
    unsigned char *encrypted_clean = mymalloc(MEMSIZE * sizeof(unsigned char));
    int rc = 0;
    int received = 0;

    const char *ender = "end";

    //cout << "Wating on receive ...";
    while ((rc = noenc_read(desc, encrypted, MEMSIZE, flag)) >= 0)
    {
	//cout << " received " << rc << " bytes\n";
	if ((rc == 3 && (strncmp(encrypted, ender, 3) == 0)))
	{
	    break;
	}

	if ((strncmp(ender, &encrypted[rc - 3], 3) == 0))
	{
	    rc = rc - 3;
	    memcpy(encrypted_clean, encrypted, rc);
	    quit = true;
	}
	else
	{
	    memcpy(encrypted_clean, encrypted, rc);
	}

	rcv_parts++;
	int decrypted_length = private_decrypt(rsa, (unsigned char *) encrypted, rc, (unsigned char *) &buffer[received]);

	//int decrypted_length = envelope_open(pClientGlobals->EVP_key, (unsigned char *) encrypted, rc, (unsigned char *) &buffer[received]);	

	if (decrypted_length == -1)
	{
	    printLastError((char*) "Error: Private Decrypt failed. Unable to decrypt message. ");
	    exit(0);
	}
	received += decrypted_length;
    }

    if (rc < 0)
	cout << "Connection reset by peer\n";

    //cout << "About to free encrypted\n";
    free(encrypted);
    //cout << "About to free encrypted_clean\n";
    free(encrypted_clean);

    return received;
}

test_decrypt(unsigned char * enc_buffer, int length, unsigned char * org_buffer, int org_buffer_length)
{
    if (!bDumpFile) return;
    unsigned char * dec_buf;
    dec_buf = (unsigned char *) mymalloc(length * sizeof(unsigned char));

    int decrypted_length = private_decrypt(pClientGlobals->my_private_rsa, (unsigned char *) enc_buffer, length, (unsigned char *) dec_buf);

    if (memcmp(dec_buf, org_buffer, org_buffer_length) != 0)
    {
	cout << "****Buffer dont match !!!!!!!!!!!\n";
	exit(-1);
    }
    FILE *fileStream;
    fileStream = fopen("test.bin", "ab");

    if (fileStream)
    {
	fseek(fileStream, 0, SEEK_END);
	fwrite(dec_buf, decrypted_length, 1, fileStream);
	fclose(fileStream);
    }

    free(dec_buf);
}

int enc_write(RSA *rsa, int desc, unsigned char *buffer, int buffer_length, int flag)
{
    int n = 0;
    char *p = buffer;
    //cout << "About to get se and recv sizes \n";

    int send_buffer_length = set_encsend_buffer_size(); //180;
    int recv_buffer_length = set_encrecv_buffer_size();
    //unsigned char *encrypted = (unsigned char*) mymalloc(recv_buffer_length * sizeof(unsigned char));
    //unsigned char *send_buff = (unsigned char*) mymalloc(send_buffer_length * sizeof(unsigned char));
    unsigned char encrypted[recv_buffer_length];
    unsigned char send_buff[send_buffer_length];

    int remaining = buffer_length;
    int bytes_sent = 0;
    const char *ender = "end";
    while (remaining > 0)
    {
	int cp_len = remaining >= send_buffer_length ? send_buffer_length : remaining;
	// cout << " cp_len = " << cp_len << endl;

	//hexdump(buffer, cp_len);
	memcpy(send_buff, &buffer[buffer_length - remaining], cp_len);
	//hexdump(send_buff, cp_len);
	remaining = remaining - cp_len;

	//int encrypted_length = private_encrypt(rsa, (unsigned char *) send_buff, cp_len, (unsigned char*) encrypted);
	int encrypted_length = public_encrypt(rsa, (unsigned char *) send_buff, cp_len, (unsigned char*) encrypted);

	//int encrypted_length = envelope_seal(&pClientGlobals->EVP_key, (unsigned char *)send_buff, cp_len, (unsigned char *)&encrypted);
	//	hexdump(send_buff, cp_len);
	//	test_decrypt((unsigned char *) encrypted, encrypted_length, send_buff , cp_len );
	//	cout << "Sleeping ...\n";
	//sleep(1);
	if (encrypted_length == -1)
	{
	    printLastError((char *) "Public Encrypt failed ");
	    exit(0);
	}
	n = noenc_write(desc, encrypted, encrypted_length, flag);

	bytes_sent += n;
    }
    // for encrypted block we need to send an extra byte
    n = noenc_write(desc, (unsigned char *) ender, 3, flag);

    //cout << "About to free encrypted\n";

    //free(encrypted);

    //cout << "About to free send_buff\n";
    //free(send_buff);

    return bytes_sent;
}

int FIRST_WRITE(int desc, unsigned char * buffer, int buffer_len)
{
    return WRITE(NULL, desc, buffer, buffer_len);
}

int WRITE(RSA *rsa, int desc, unsigned char * buffer, int buffer_len)
{
    int sent = 0;
    fflush(stdout);

    //    sprintf(buffer, "HTTP/1.0 200 OK\r\nServer: jdbhttpd/0.1.0\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>Method Not Implemented\r\n</TITLE></HEAD>\r\n<BODY><h1>Hello World.</h1>\r\n<p>%s</p></BODY></HTML>\r\n", buffer);
    //    buffer_len = strlen(buffer);

    //printf("Sending : %s (%d bytes)\r\n", buffer, buffer_len);
    rsa ? sent = enc_write(rsa, desc, buffer, buffer_len, 0) : sent = noenc_write(desc, buffer, buffer_len, 0);

    //cout << "Bytes Sent " <<  sent << endl;
    return sent;
}
