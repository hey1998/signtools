#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <openssl/pem.h>

static int __inline checkPrefix(const char *s, const char *p)
{
	return !memcmp(s, p, strlen(p));
}

static int __inline putString(BIO * b, const char *str)
{
	int n = strlen(str);
	return n == BIO_write(b, str, n);
}

static int putValue(BIO * b, const char *k, const char *v)
{
	return putString(b, k) && putString(b, ": ") &&
		putString(b, v) && putString(b, "\r\n");
}

static int putHeader(BIO * b)
{
	return putValue(b, "Manifest-Version", "1.0") &&
		putValue(b, "Created-By", "1.0 (Android SignApk)") &&
		putString(b, "\r\n");
}

static int putBanner(BIO * b, const char *v)
{
	return putValue(b, "Signature-Version", "1.0") &&
		putValue(b, "Created-By", "1.0 (Android SignApk)") &&
		putValue(b, "SHA1-Digest-Manifest", v) &&
		putString(b, "\r\n");
}

static void __inline *searchSuffix(const char *s1, size_t n1, const char *s2, size_t n2)
{
	if (n1 >= n2 && n2 > 0)
		for (; (s1 = memchr(s1, *s2, n1)) != NULL; s1++)
			if (memcmp(s1, s2, n2) == 0)
				return (void *) s1;
	return NULL;
}

static size_t getSuBlock(const void *in, const size_t size, const char *suffix)
{
	const void *p;
	if ((p = searchSuffix(in, size, suffix, strlen(suffix))) != NULL)
		return (char *) p - (char *) in + strlen(suffix);
	return 0;
}

static int makeSignatureFile(BIO * b, void *buffer, int length)
{
	int n, ret;
	EVP_MD_CTX mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned char md_decode[(EVP_MAX_MD_SIZE + 2) / 3 * 4 + 1];
	unsigned int md_len;
	EVP_DigestInit(&mdctx, EVP_sha1());
	EVP_DigestUpdate(&mdctx, buffer, length);
	EVP_DigestFinal(&mdctx, md_value, &md_len);
	EVP_EncodeBlock(md_decode, md_value, md_len);
	if (!(ret = putBanner(b, (char *) md_decode)))
		return ret;
	for (; (ret = getSuBlock(buffer, length, "\r\n\r\n")) != 0; (char *) buffer += ret, length -= ret) {
		if (!checkPrefix(buffer, "Name: ") || !(n = getSuBlock(buffer, ret, "\r\n")))
			continue;
		if (n != BIO_write(b, buffer, n))
			break;
		EVP_DigestInit(&mdctx, EVP_sha1());
		EVP_DigestUpdate(&mdctx, buffer, ret);
		EVP_DigestFinal(&mdctx, md_value, &md_len);
		EVP_EncodeBlock(md_decode, md_value, md_len);
		if (!putValue(b, "SHA1-Digest", (char *) md_decode) || !putString(b, "\r\n"))
			break;
	}
	return !ret;
}

static X509 *readPublicKey(const char *file)
{
	BIO *b;
	X509 *x;
	if ((b = BIO_new(BIO_s_file())) == NULL || BIO_read_filename(b, file) == 0)
		return NULL;
	x = PEM_read_bio_X509(b, NULL, 0, NULL);
	BIO_free(b);
	return x;
}

static EVP_PKEY *readPrivateKey(const char *file)
{
	BIO *b;
	EVP_PKEY *k;
	if ((b = BIO_new(BIO_s_file())) == NULL || BIO_read_filename(b, file) == 0)
		return NULL;
	k = d2i_PrivateKey_bio(b, NULL);
	BIO_free(b);
	return k;
}

static int reimp_PKCS7_final(PKCS7 * p7, void *data, int length)
{
	BIO *p7bio;
	int ret = 0;
	if (!(p7bio = PKCS7_dataInit(p7, NULL)))
		return 0;
	BIO_write(p7bio, data, length);
	(void) BIO_flush(p7bio);
	if (!PKCS7_dataFinal(p7, p7bio))
		goto err;
	ret = 1;
err:
	BIO_free_all(p7bio);
	return ret;
}

static PKCS7 *reimp_PKCS7_sign(X509 * signcert, EVP_PKEY * pkey, STACK_OF(X509) * certs, int flags)
{
	PKCS7 *p7;
	int i;
	if (!(p7 = PKCS7_new()))
		return NULL;
	if (!PKCS7_set_type(p7, NID_pkcs7_signed))
		goto err;
	if (!PKCS7_content_new(p7, NID_pkcs7_data))
		goto err;
	if (!PKCS7_sign_add_signer(p7, signcert, pkey, NULL, flags))
		goto err;
	if (!(flags & PKCS7_NOCERTS))
		for (i = 0; i < sk_X509_num(certs); i++)
			if (!PKCS7_add_certificate(p7, sk_X509_value(certs, i)))
				goto err;
	if (flags & PKCS7_DETACHED)
		PKCS7_set_detached(p7, 1);
	if (flags & (PKCS7_STREAM | PKCS7_PARTIAL))
		return p7;
err:
	PKCS7_free(p7);
	return NULL;
}

static int reimp_i2d_ASN1_bio_stream(BIO * out, ASN1_VALUE * val, int flags, const ASN1_ITEM * it)
{
	if (!(flags & SMIME_STREAM))
		return ASN1_item_i2d_bio(it, out, val);
	return 0;
}

int main(int argc, char **argv)
{
	BIO *cbio = NULL, *sbio = NULL, *tbio = NULL;
	X509 *scert = NULL;
	EVP_PKEY *skey = NULL;
	PKCS7 *p7 = NULL;
	const int flags = PKCS7_DETACHED | PKCS7_PARTIAL | PKCS7_BINARY | PKCS7_NOCHAIN | PKCS7_NOATTR;
	mz_zip_archive zip_in, zip_out;
	unsigned int i;
	int ret = -1;

	if (argc != 5) {
		fprintf(stdout, "Usage: %s publickey.x509[.pem] privatekey.pk8 input.jar output.jar\n", argv[0]);
		return -2;
	}

	memset(&zip_in, 0, sizeof(mz_zip_archive));
	memset(&zip_out, 0, sizeof(mz_zip_archive));
	EVP_add_digest(EVP_sha1());
	if ((scert = readPublicKey(argv[1])) == NULL || (skey = readPrivateKey(argv[2])) == NULL) {
		fprintf(stderr, "SignatureException: error in reading signer info\n");
		goto err;
	}
	if (!mz_zip_reader_init_file(&zip_in, argv[3])
		|| !mz_zip_writer_init_file(&zip_out, argv[4])) {
		fprintf(stderr, "ZipException: error in opening zip file\n");
		goto err;
	}
	if ((cbio = BIO_new(BIO_s_mem())) == NULL || !putHeader(cbio)) {
		fprintf(stderr, "SignatureException: failed to initialize\n");
		goto err;
	}
	for (i = 0; i < mz_zip_reader_get_num_files(&zip_in); i++) {
		mz_zip_archive_file_stat file_stat;
		size_t uncomp_size;
		EVP_MD_CTX mdctx;
		unsigned char md_value[EVP_MAX_MD_SIZE];
		unsigned char md_decode[(EVP_MAX_MD_SIZE + 2) / 3 * 4 + 1];
		unsigned int md_len;
		void *p;
		int status;
		if (!mz_zip_reader_file_stat(&zip_in, i, &file_stat)) {
			fprintf(stderr, "ZipException: error in reading zip file\n");
			goto err;
		}
		if (mz_zip_reader_is_file_a_directory(&zip_in, i) || checkPrefix(file_stat.m_filename, "META-INF"))
			continue;
		if (!(p = mz_zip_reader_extract_to_heap(&zip_in, i, &uncomp_size))) {
			fprintf(stderr, "ZipException: error in extracting zip file\n");
			goto err;
		}
		status = !mz_zip_writer_add_mem(&zip_out, file_stat.m_filename, p, uncomp_size, MZ_BEST_COMPRESSION);
		EVP_DigestInit(&mdctx, EVP_sha1());
		EVP_DigestUpdate(&mdctx, p, uncomp_size);
		EVP_DigestFinal(&mdctx, md_value, &md_len);
		free(p);
		if (status) {
			fprintf(stderr, "ZipException: error in writing zip file\n");
			goto err;
		}
		EVP_EncodeBlock(md_decode, md_value, md_len);
		if (!putValue(cbio, "Name", file_stat.m_filename) || !putValue(cbio, "SHA1-Digest", (char *) md_decode)
			|| !putString(cbio, "\r\n")) {
			fprintf(stderr, "SignatureException: adding digests to manifest failed\n");
			goto err;
		}
	}
	if ((sbio = BIO_new(BIO_s_mem())) == NULL ||
		!makeSignatureFile(sbio, ((BUF_MEM *) cbio->ptr)->data, ((BUF_MEM *) cbio->ptr)->length)) {
		fprintf(stderr, "SignatureException: error in writing signature file\n");
		goto err;
	}
	if ((tbio = BIO_new(BIO_s_mem())) == NULL ||
		(p7 = reimp_PKCS7_sign(scert, skey, NULL, flags)) == NULL ||
		reimp_PKCS7_final(p7, ((BUF_MEM *) sbio->ptr)->data, ((BUF_MEM *) sbio->ptr)->length) == 0 ||
		reimp_i2d_ASN1_bio_stream(tbio, (ASN1_VALUE *) p7, flags, ASN1_ITEM_rptr(PKCS7)) == 0) {
		fprintf(stderr, "SignatureException: error in writing signature block\n");
		goto err;
	}
	if (!mz_zip_writer_add_mem(&zip_out, "META-INF/MANIFEST.MF", ((BUF_MEM *) cbio->ptr)->data, ((BUF_MEM *) cbio->ptr)->length, MZ_BEST_COMPRESSION)
		|| !mz_zip_writer_add_mem(&zip_out, "META-INF/CERT.SF", ((BUF_MEM *) sbio->ptr)->data, ((BUF_MEM *) sbio->ptr)->length, MZ_BEST_COMPRESSION)
		|| !mz_zip_writer_add_mem(&zip_out, "META-INF/CERT.RSA", ((BUF_MEM *) tbio->ptr)->data, ((BUF_MEM *) tbio->ptr)->length, MZ_BEST_COMPRESSION)) {
		fprintf(stderr, "ZipException: error in adding zip file\n");
		goto err;
	}
	ret = 0;
err:
	if (p7)
		PKCS7_free(p7);
	if (scert)
		X509_free(scert);
	if (skey)
		EVP_PKEY_free(skey);
	if (cbio)
		BIO_free(cbio);
	if (sbio)
		BIO_free(sbio);
	if (tbio)
		BIO_free(tbio);
	mz_zip_reader_end(&zip_in);
	mz_zip_writer_finalize_archive(&zip_out);
	mz_zip_writer_end(&zip_out);
	if (ret)
		remove(argv[4]);
	return ret;
}
