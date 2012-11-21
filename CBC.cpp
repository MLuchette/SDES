/* CBC.cpp
	Matthew Luchette
	Programming Assignment 4: CBC Mode
	CPSC 460
	This program implements encryption and decryption of randomly generated (string, key) pairs
	using the SDES algorithm and CBC Mode
*/
#include <iostream>
#include <string>
#include <ctime>
#include <stdio.h>
using namespace std;

string CBC(string, string, string, int);
string CBCDecryption(string, string, string, int);
string SDESEncryption(string, string, int);
string SDESDecryption(string, string, int);
string findKey(string, int);
string functionF(string, string);
string XOR(string, string);
string S1Box(string);
string S2Box(string);
string randomString(int);
string header();
int bitsDifferent(string, string);

int main()
{
	string ciphertext;
	string ciphertext2;
	string plaintext2;
	string decryption;
	//Initialize Random 48 bit plaintext
	string plaintext = randomString(48);
	cout	<< "Generating your plaintext..." << endl
			<< "Press any key to grab your key!" << endl;
	plaintext2 = plaintext;
	cin.get();
	system("CLS");
	//Initialize Random 9 bit key
	string key = randomString(9);
	cout	<< "Generating your key..." << endl
			<< "Press any key to grab your initialization vector!" << endl;
	cin.get();
	system("CLS");
	//Initialize Random 12 bit initialization vector
	string IV = randomString(12);
	cout	<< "Generating your initialization vector..." << endl
			<< "Press any key to do some SDES in CBC mode!" << endl;
	cin.get();
	system("CLS");

	//Print out unnecessary header
	cout	<< header();

	//Print out original plaintext P, key K and initialization vector IV
	cout	<< "Original Plaintext:\t" << plaintext << endl
			<< "\nKey:\t\t\t" << key << endl << endl
			<< "Initialization Vector:\t" << IV << endl << endl
			<< "\tItem #1: Create a plaintext message consisting of 48 bits,\n\t\t and show how it encrypts and decrypts using CBC." << endl << endl;
	//Encrypt plaintext using CBC (4 rounds of SDES)
	ciphertext = CBC(key, plaintext, IV, 4);
	cout	<< "Ciphertext:\t\t" << ciphertext << endl << endl
		<< "Security check:\t\t" << bitsDifferent(ciphertext, plaintext) << " bits have been altered." << endl << endl;
	//Decrypt ciphertext using CBC (4 rounds of SDES)
	decryption = CBCDecryption(key, ciphertext, IV, 4);
	cout	<< "Decryption:\t\t" << decryption << endl << endl;
	if(bitsDifferent(decryption,plaintext) == 0)
		cout << "\tDecryption process verified, original plaintext obtained!" << endl << endl;
	else
		cout << "\tSomething went wrong..." << endl << endl;
	cout	<< "\tItem #2: Suppose you have 2 plaintexts that differ in the 14th bit.\n\t\t Show the effect that this has on the corresponding ciphertexts."
			<< endl << endl;
	//Change the 14th bit of the (mostly) identical plaintext2
	if(plaintext2[13] == '0')
		plaintext2[13] = '1';
	else
		plaintext2[13] = '0';
	//Now encrypt plaintext 2, and find out how different it is from the encryption of the original encryption
	ciphertext2 = CBC(key, plaintext2, IV, 4);
	cout	<< "Plaintext:\t\t" << plaintext << endl << endl
			<< "Ciphertext:\t\t" << ciphertext << endl << endl
			<< "~Plaintext:\t\t" << plaintext2 << endl << endl
			<< "~Ciphertext:\t\t" << ciphertext2 << endl << endl
			<< "Error check:\t\t" << bitsDifferent(ciphertext2, ciphertext) << " bits were damaged by changing bit 14." << endl << endl;

	return 0;
}

////////////////////////////////////////////////////////////////
//CBC Mode Encryption
////////////////////////////////////////////////////////////////
string CBC(string key, string plaintext, string IV, int rounds)
{
	string ciphertext1;
	string ciphertext2;
	string ciphertext3;
	string ciphertext4;
	string ciphertext;
	//Divide plaintext into 4 12-bit parts
	ciphertext1.append(plaintext, 0, 12);
	ciphertext2.append(plaintext, 12, 12);
	ciphertext3.append(plaintext, 24, 12);
	ciphertext4.append(plaintext, 36, 12);
	
	//Do [rounds] of SDES on each block of ciphertext using CBC Mode
	//P1 XOR C0
	ciphertext1 = XOR(ciphertext1, IV);
	//Ek(P1 XOR IV)
	for(int i = 1; i <= rounds; i++)
		ciphertext1 = SDESEncryption(key, ciphertext1, i);
	//P2 XOR C1
	ciphertext2 = XOR(ciphertext2, ciphertext1);
	//Ek(P2 XOR C1)
	for(int i = 1; i <= rounds; i++)
		ciphertext2 = SDESEncryption(key, ciphertext2, i);
	//P3 XOR C2
	ciphertext3 = XOR(ciphertext3, ciphertext2);
	//Ek(P3 XOR C2)
	for(int i = 1; i <= rounds; i++)
		ciphertext3 = SDESEncryption(key, ciphertext3, i);
	//P4 XOR C3
	ciphertext4 = XOR(ciphertext4, ciphertext3);
	//Ek(P4 XOR C3)
	for(int i = 1; i <= rounds; i++)
		ciphertext4 = SDESEncryption(key, ciphertext4, i);

	// Return the ciphertext
	return ciphertext1 + ciphertext2 + ciphertext3 + ciphertext4;
}

////////////////////////////////////////////////////////////////
//CBC Mode Decryption
////////////////////////////////////////////////////////////////
string CBCDecryption(string key, string ciphertext, string IV, int rounds)
{
	string plaintext1;
	string plaintext2;
	string plaintext3;
	string plaintext4;
	//Divide ciphertext into 4 12-bit parts
	plaintext1.append(ciphertext, 0, 12);
	plaintext2.append(ciphertext, 12, 12);
	plaintext3.append(ciphertext, 24, 12);
	plaintext4.append(ciphertext, 36, 12);
	//Dk(C4)
	for(int i = rounds; i > 0; i--)
		plaintext4 = SDESDecryption(key, plaintext4, i);
	//P4 = C3 XOR Dk(C4)
	plaintext4 = XOR(plaintext3, plaintext4);
	//Dk(C3)
	for(int i = rounds; i > 0; i--)
		plaintext3 = SDESDecryption(key, plaintext3, i);
	//P4 = C2 XOR Dk(C3)
	plaintext3 = XOR(plaintext2, plaintext3);
	//Dk(C2)
	for(int i = rounds; i > 0; i--)
		plaintext2 = SDESDecryption(key, plaintext2, i);
	//P4 = C1 XOR Dk(C2)
	plaintext2 = XOR(plaintext1, plaintext2);
	//Dk(C1)
	for(int i = rounds; i > 0; i--)
		plaintext1 = SDESDecryption(key, plaintext1, i);
	//P4 = IV XOR Dk(C1)
	plaintext1 = XOR(IV, plaintext1);
	
	// Return the plaintext
	return (plaintext1 + plaintext2 + plaintext3 + plaintext4);
}

////////////////////////////////////////////////////////////////
//SDES Encryption Function
////////////////////////////////////////////////////////////////
string SDESEncryption(string key, string plaintext, int round)
{
	//Declare variables
	string Li;
	string Ri;
	string Ln;
	string Rn;
	string K;
	string f;
	//Find the key for the round
	K = findKey(key, round);
	//Split the plaintext into initial Li and Ri
	Li.append(plaintext, 0, 6);
	Ri.append(plaintext, 6, 6);
	//Step 1: Ln = Ri
	Ln = Ri;
	//Step 2: Rn = L0 XOR f(Ri,Kround)
	//Find f(Ri, Kround)
	f.append(functionF(Ri, K));
	//Now find Rn = Li XOR f(Ri, Kround)
	Rn.append(f);
	Rn = XOR(Li, f);
	//Finish the round by concatenating  and returning Ln+Rn;
	return (Ln + Rn);
}

////////////////////////////////////////////////////////////////
//SDES Decryption Function
////////////////////////////////////////////////////////////////
string SDESDecryption(string key, string ciphertext, int round)
{
	//Declare variables
	string Li;
	string Ri;
	string Ln;
	string Rn;
	string K;
	string f;
	//Find the key for the round
	K = findKey(key, round);
	//Split the ciphertext into initial Li and Ri
	Li.append(ciphertext, 0, 6);
	Ri.append(ciphertext, 6, 6);
	//Step 1: Rn = Li
	Rn = Li;
	//Step 2: Ln = Ri XOR f(Ln, K)
	//Find f(Ln, K)
	f.append(functionF(Rn, K));
	//Now find Ln = Ri XOR f(Ln, K)
	Ln.append(f);
	Ln = XOR(Ri, f);
	//Finish the round by concatenating and returning Ln + Rn
	return (Ln + Rn);

}

////////////////////////////////////////////////////////////////
//A function to find the key based on what round it is
////////////////////////////////////////////////////////////////
string findKey(string key, int round)
{
	//Get the key for the round
	string K;
	if(round == 1)
		K.append(key, 0, 8);
	else if(round == 2)
		K.append(key, 1, 8);
	else if(round == 3)
	{
		K.append(key, 2, 7);
		K.append(key, 0, 1);
	}
	else if(round == 4)
	{
		K.append(key, 3, 6);
		K.append(key, 0, 2);
	}
	return K;
}

////////////////////////////////////////////////////////////////
//The F Function (f(Ri, Ki+1))
////////////////////////////////////////////////////////////////
string functionF(string R, string K)
{
	char tmp;
	string s1;
	string s2;
	//Expand Ri to find E(Ri)
	R.append(R, 4, 2);
	tmp = R[3];
	R[5] = R[2];
	R[4] = tmp;
	R[3] = R[2];
	R[2] = tmp;
	//XOR E(Ri) with Kround to find S-Box inputs
	R = XOR(R, K);
	s1.append(R, 0, 4);
	s2.append(R, 4, 4);
	//Find f(Ri, Kround) by concatenating S1Box(s1) + S2Box(s2)
	return S1Box(s1) + S2Box(s2);
}

////////////////////////////////////////////////////////////////
//The XOR Function
////////////////////////////////////////////////////////////////
string XOR(string x, string y)
{
	for(unsigned int i = 0; i < x.length(); i++)
	{
		if(x[i] == y[i])
			x[i] = '0';
		else if(x[i] != y[i])
			x[i] = '1';
	}
	return x;
}

////////////////////////////////////////////////////////////////
//S1-Box Function
////////////////////////////////////////////////////////////////
string S1Box(string s1)
{
	//Define S1-Box rows 1 and 2
	string row1[8] = {"101", "010", "001", "110", "011", "100", "111", "000"};
	string row2[8] = {"001", "100", "110", "010", "000", "111", "101", "011"};
	int column = 0;
	//If bits start with a 0, use row 1
	if(s1[0] == '0')
	{
		//Convert remaining 3 bits to decimal
		if(s1[1] == '1')
			column += 4;
		if(s1[2] == '1')
			column += 2;
		if(s1[3] == '1')
			column += 1;
		//Return the 3 bit pattern in the respective column
		return row1[column];
	}
	//If bits start with a 1, use row 2
	else if(s1[0] == '1')
	{
		//Convert remaining 3 bits to decimal
		if(s1[1] == '1')
			column += 4;
		if(s1[2] == '1')
			column += 2;
		if(s1[3] == '1')
			column += 1;
		//Return the 3 bit pattern in the respective column
		return row2[column];
	}
	else
		//Something went wrong (very wrong)
		return "ERROR";
}

////////////////////////////////////////////////////////////////
//S2-Box Function
////////////////////////////////////////////////////////////////
string S2Box(string s2)
{
	//Define S1-Box rows 1 and 2
	string row1[8] = {"100", "000", "110", "101", "111", "001", "011", "010"};
	string row2[8] = {"101", "011", "000", "111", "110", "010", "001", "100"};
	int column = 0;
	//If bits start with a 0, use row 1
	if(s2[0] == '0')
	{
		//Convert the remaining 3 bits to decimal
		if(s2[1] == '1')
			column += 4;
		if(s2[2] == '1')
			column += 2;
		if(s2[3] == '1')
			column += 1;
		//Return the 3 bit pattern in the respective column
		return row1[column];
	}
	//If bits start with a 1, use row 2
	else if(s2[0] == '1')
	{
		//Convert the remaining 3 bits to decimal
		if(s2[1] == '1')
			column += 4;
		if(s2[2] == '1')
			column += 2;
		if(s2[3] == '1')
			column += 1;
		//Return the 3 bit pattern in the respective column
		return row2[column];
	}
	else
		//Something went wrong (very wrong)
		return "ERROR";
}

////////////////////////////////////////////////////////////////
//Function to generate a random bit string
////////////////////////////////////////////////////////////////
string randomString(int length)
{
	//Use the most random number as a seed for PRNG
	srand(time(0));
	int randomNumber;
	string randomBit;
	string randomString;
	for(int k = 0; k < length; k++)
	{
		randomNumber = rand() % 2;
		if(randomNumber == 0)
			randomBit = "0";
		else if(randomNumber == 1)
			randomBit = "1";
		randomString.append(randomBit);
	}
	return randomString;
}

int bitsDifferent(string s1, string s2)
{
	string t = XOR(s1, s2);
	int ctr = 0;
	for(unsigned int i = 0; i < t.length(); i++)
		if(t[i] == '1')
			ctr++;
	return ctr;
}

////////////////////////////////////////////////////////////////
//Function to print out header
////////////////////////////////////////////////////////////////
string header()
{
	string header = "\t\t*****************\t\t*****************\n\t\t\t       SDES CBC MODE DEMO\t\t\t\n\t\t*****************\t\t*****************\n";
	return header;
}