#include <iostream>
#include <cstdlib>
#include <string.h>
#include "KrakenKeys.h" //Key creation

using namespace std;

int main(int argc, char *argv[])
{
    do {

    cout << "///////////////////////// KRAKEN /////////////////////////" << endl;
    cout << "/////////////// ed25519 Key Pair generator //////////////" << endl;
    cout << endl;

    int choix;

    cout << "Please, choose an action" << endl;
    cout << endl;
    cout << "1 - Create ed25519 ECC public and private key pair" << endl;
    cout << "2 - About KRAKEN" << endl;
    cout << "3 - Leave" << endl;

    cout << endl;

    cin >> choix;
    cout << endl;
    cout << "/////////////////////////////////////////////////" << endl;
    cout << endl;

        if (choix > 3){
                choix = 0;
        }

        while(cin.fail())
    {
        cin.clear();
        cin.ignore();
        choix = 0;
    }

    switch (choix)
    {
        case 0:
            system("clear");
            cout << "Please, choose correct number from menu" << endl;
            cout << endl;
                break;
        case 1:
            system("clear");
            CreateKeys();
            cout << endl;
                break;
        case 2:
            system("clear");
            cout << "KRAKEN is an experiments made for educational purposes." << endl;
            cout << "You are free to use, modify and sell this product." << endl;
            cout << "This program comes with ABSOLUTELY NO WARRANTY !" << endl;
            cout << endl;
            cout << endl;
            cout << endl;
                break;
        case 3:
            system("clear");
            cout << "////// KRAKEN STOPPED //////" << endl;
            return 0;
                break;
    }

} while (1);


}
