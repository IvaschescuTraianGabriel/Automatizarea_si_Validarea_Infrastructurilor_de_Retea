# Automatizarea_si_Validarea_Infrastructurilor_de_Retea


Link repository: https://github.com/IvaschescuTraianGabriel/Automatizarea_si_Validarea_Infrastructurilor_de_Retea.git


Cerințe Preliminare (Prerequisites)
Asigură-te că ai următoarele aplicații instalate pe mașina ta de lucru:

O platformă de virtualizare: VMware Workstation Pro 17 (recomandat) sau o alternativă similară.

GNS3: Platforma de emulare a rețelelor, incluzând GNS3 VM.

Imagini Software pentru Dispozitive: Imaginile .qcow2 sau .vmdk corespunzătoare pentru dispozitivele Cisco și Ubuntu.

PyCharm Professional: Sau un alt IDE care suportă interpretoare Python la distanță (remote SSH interpreter).

Git: Pentru a clona repository-ul.



Procesul de Instalare
Clonarea Repository-ului: Descarcă sau clonează repository-ul proiectului pe stația de lucru locală.

Configurarea Mediului GNS3: Pornește GNS3, importă imaginile necesare pentru dispozitive și construiește topologia de rețea conform diagramei prezentate în lucrare.

Pregătirea Serverului de Automatizare: Pornește topologia în GNS3 și asigură-te că instanța UbuntuServer este funcțională, are conectivitate la rețea și are o versiune compatibilă de Python 3 instalată.

Configurarea Mediului de Dezvoltare (PyCharm):

Deschide folderul proiectului clonat în PyCharm.

Configurează un remote SSH interpreter care să se conecteze la instanța UbuntuServer din GNS3.

Direct din interfața PyCharm, folosește funcționalitatea de management a pachetelor pentru a crea un nou mediu virtual pe serverul distant și pentru a instala dependențele specificate în fișierul requirements.txt.



Execuția Scriptului de Automatizare
Datorită configurării interpretorului la distanță, rularea întregului flux de automatizare este un proces simplu.

Asigură-te că topologia GNS3 este pornită și că toate dispozitivele s-au inițializat complet.

În PyCharm, deschide fișierul principal al proiectului: main.py.

Rulează fișierul folosind opțiunea "Run" din IDE (ex: click dreapta -> Run 'main' sau butonul ▶).

PyCharm se va conecta automat prin SSH la serverul Ubuntu, va activa mediul virtual corespunzător și va executa scriptul. Output-ul detaliat al procesului de automatizare va fi afișat în timp real în fereastra terminalului de execuție "Run" din cadrul PyCharm, oferind vizibilitate completă asupra procesului.
