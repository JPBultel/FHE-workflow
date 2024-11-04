#include "openfhe.h"

using namespace lbcrypto;

//binary decision trees
typedef struct bdt
{
	std::vector<int64_t> root;
	bdt* left;
	bdt* right;
} bdt;

//binary decision trees encoded as plaintexts
typedef struct bdt_pt
{
	Plaintext root;
	bdt_pt* left;
	bdt_pt* right;
} bdt_pt;

//encrypted binary decision trees
typedef struct bdt_ct
{
	Ciphertext<DCRTPoly> root;
	bdt_ct* left;
	bdt_ct* right;
} bdt_ct;

//encoding a binary decision tree
bdt_pt bdt_encode(CryptoContext<DCRTPoly> cc, bdt tree)
{
	bdt_pt result;
	result.root = cc->MakePackedPlaintext(tree.root);
	result.left = new bdt_pt();
	result.right = new bdt_pt();
	if(tree.left!=NULL)
	{
	  *(result.left) = bdt_encode(cc, *(tree.left));
	}
	else
	{
	  result.left = NULL;
	}
	if(tree.right!=NULL)
	{
	  *(result.right) = bdt_encode(cc, *(tree.right));
	}
	else
	{
	  result.right=NULL ;
	}
	return result;
}

//encryption of a binary decision tree
bdt_ct bdt_encrypt(CryptoContext<DCRTPoly> cc, bdt_pt tree, const PublicKey<DCRTPoly> pk)
{
	bdt_ct result;
	result.root = cc->Encrypt(pk, tree.root);
	result.left = new bdt_ct();
	result.right = new bdt_ct();
	if(tree.left!=NULL)
	{
	  *(result.left) = bdt_encrypt(cc, *(tree.left), pk);
	}
	else
	{
	  result.left = NULL;
	}
	if(tree.right!=NULL)
	{
	  *(result.right) = bdt_encrypt(cc, *(tree.right), pk);
	}
	else
	{
	  result.right = NULL;
	}
	return result;
}

//decryption of a binary decision tree
bdt_pt bdt_decrypt(CryptoContext<DCRTPoly> cc, bdt_ct tree, const PrivateKey<DCRTPoly> sk)
{
	bdt_pt result;
	cc->Decrypt(sk, tree.root, &(result.root));
	result.left = new bdt_pt();
	result.right = new bdt_pt();
	if(tree.left!=NULL)
	{
	  *(result.left) = bdt_decrypt(cc, *(tree.left), sk);
	}
	else
	{
	  result.left = NULL;
	}
	if(tree.right!=NULL)
	{
	  *(result.right) = bdt_decrypt(cc, *(tree.right), sk);
	}
	else
	{
	  result.right = NULL;
	}
	return result;
}	

int main()
{
      //cryptocontext setting
      CCParams<CryptoContextBGVRNS> parameters;
      parameters.SetMultiplicativeDepth(2);
      parameters.SetPlaintextModulus(65537);
      
      CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
      cc->Enable(PKE);
      cc->Enable(KEYSWITCH);
      cc->Enable(LEVELEDSHE);
      
      //key generation
      KeyPair<DCRTPoly> keyPair;
      keyPair = cc->KeyGen();
      const PublicKey<DCRTPoly> pk = keyPair.publicKey;
      const PrivateKey<DCRTPoly> sk = keyPair.secretKey;
      
      
      //constructing a tree
      bdt tree;
      
      //(nodes)
      tree.root = {1};
      
      tree.left = new bdt();
      tree.right = new bdt();
      (tree.left)->root = {1};
      (tree.right)->root = {0};
      
      
      (tree.left)->left = new bdt();
      (tree.left)->right = new bdt();
      (tree.right)->left = new bdt();
      (tree.right)->right = new bdt();
      (tree.left)->left->root = {0};
      (tree.left)->right->root = {0};
      (tree.right)->left->root = {1};
      (tree.right)->right->root = {0};
       
      //(leaves)
      (tree.left)->left->left = NULL;
      (tree.left)->left->right = NULL;
      (tree.left)->right->left = NULL;
      (tree.left)->right->right = NULL;
      (tree.right)->left->left = NULL;
      (tree.right)->left->right = NULL;
      (tree.right)->right->left = NULL;
      (tree.right)->right->right = NULL;
      
      // printing the nodes
      std::cout << tree.root << (tree.left)->root << (tree.right)->root << (tree.left)->left->root << (tree.left)->right->root << (tree.right)->left->root << (tree.right)->right->root << std::endl;
      
      //encoding
      bdt_pt encoded_tree = bdt_encode(cc, tree);
      
      //printing the encoded tree
      std::cout << encoded_tree.root << (encoded_tree.left)->root << (encoded_tree.right)->root << (encoded_tree.left)->left->root << (encoded_tree.left)->right->root << (encoded_tree.right)->left->root << (encoded_tree.right)->right->root << std::endl;
      
      //encrypting
      bdt_ct encrypted_tree = bdt_encrypt(cc, encoded_tree, pk);
      
      //decrypting
      bdt_pt result = bdt_decrypt(cc, encrypted_tree, sk);
      
      //printing the result
      std::cout << result.root << (result.left)->root << (result.right)->root << (result.left)->left->root << (result.left)->right->root << (result.right)->left->root << (result.right)->right->root << std::endl;
      
      return 0;
}
      
      
      

