Nomenclature fichiers pcapng:

    K = Kacper
    Q = Querol
    M = Message
    A = Appel audio
    V = Appel vidéo
    W = WiFi
    E = Ethernet
    G = 4G
    B = Big file
    / = Small/Medium file
    -60sec : Appel audio ou vidéo de 60 secondes
    -MissedCall : Appel manqué par K ou Q
    -LeaveBeforeResponse : Appel quitté avant que l'autre 
			   ne puisse répondre

Utilisation des fichiers python : 

	1. Assurez vous d'avoir pyshark 0.5.3 installé et d'être dans le 
	   dossier .\analyse_pyshark
	2. python *.py
	3. Les statistiques se trouveront dans le fichier texte portant 
	   le même nom *.txt
	Remarque: Le résumé des statistiques se trouve à la fin de *.txt
	Remarque 2: L'output de data_size.py n'est pas formaté, le calcul
		    des moyennes est fait manuellement