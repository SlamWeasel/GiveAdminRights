using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RichtlinienCheck_File
{
    #pragma warning disable CS8600 // Unterdrückt die Warnung, dass ein Wert NULL sein kann, was in jedem Fall sowieso abgedeckt ist!
    #pragma warning disable CS8602 // Unterdrückt die Warnung, dass ein Wert NULL sein kann, was in jedem Fall sowieso abgedeckt ist!
    #pragma warning disable IDE1006 // Unterdrückt einen Fehler, der keiner ist!!!!
    class Program
    {
        static string user = Environment.UserName;

        static void Main(string[] args)
        {

            //Console.SetWindowSize(50, 10);
            //Console.SetBufferSize(50, 10);
            string[] paths = new string[]{      //Eingabe des Ordners, den man auf die Berechtigungen überprüfen will!
                            @"\\nt-file\home"/*$\" + user + @"\Documents",
                            @"\\nt-file\home$\" + Environment.UserName + @"\Eigene Dateien",
                            @"\\nt-file\home$\" + Environment.UserName + @"\Anwendungsdateien"*/
                        };

            /*Console.WriteLine(  "\n=======================================================\n" +
                                @"               _     _                     _ " + "\n" +
                                @"     /\       | |   | |                   | |" + "\n" +
                                @"    /  \   ___| |__ | |_ _   _ _ __   __ _| |" + "\n" +
                                @"   / /\ \ / __| '_ \| __| | | | '_ \ / _` | |" + "\n" +
                                @"  / ____ \ (__| | | | |_| |_| | | | | (_| |_|" + "\n" +
                                @" /_/    \_\___|_| |_|\__|\__,_|_| |_|\__, (_)" + "\n" +
                                @"                                      __/ |  " + "\n" +
                                @"                                     |___/   " + "\n" +
                                "=======================================================\n" +
                                "\n" +
                                "Dieses Fenster darf nicht geschlossen werden. Es prüft die Fixemer-Administrator-Berechtigungen!\n" +
                                "\n" +
                                "Wenn die Überprüfung ohne Probleme abgeschlossen ist wird sich das Fenster selbst schließen!\n" +
                                "\n" +
                                "\n" +
                                @" ___   _      ___   _      ___   _      ___   _      ___   _  "+"\n"+
                                @"[(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=| "+"\n"+
                                @" '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_| "+"\n"+
                                @"/mmm/  /     /mmm/  /     /mmm/  /     /mmm/  /     /mmm/  /  "+"\n"+
                                @"      |____________|____________|____________|____________|   "+"\n"+
                                @"                            |            |            |       "+"\n"+
                                @"       Beep Beep        ___  \_      ___  \_      ___  \_     "+"\n"+
                                @"    Datenstrom         [(_)] |=|    [(_)] |=|    [(_)] |=|    "+"\n"+
                                @"                        '-`  |_|     '-`  |_|     '-`  |_|    "+"\n"+
                                @"                       /mmm/        /mmm/        /mmm/");*/

            foreach (string path in paths)
            {
                try
                {
                    //Ziehen aller Regeln, wer Berechtigung auf das Verzeichnis hat
                    DirectoryInfo di = new DirectoryInfo(path);
                    DirectorySecurity acl = di.GetAccessControl();
                    AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(NTAccount));
                    IdentityReference netAdmin = new NTAccount(@"...");

                    //Prüfen, ob Netzadministartor Berechtigungen hat
                    bool AdminIsIn = false;
                    /*foreach (AuthorizationRule rule in rules)
                        if (rule.IdentityReference.ToString().Equals(@"..."))
                            AdminIsIn = true; //Setzt den Wert auf Wahr, sobald der Administrator gefunden wird*/

                    if(acl.GetOwner(typeof(SecurityIdentifier)).ToString() != netAdmin.ToString())
                    {
                        /*acl.AddAccessRule(new FileSystemAccessRule(netAdmin, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
                        acl.AddAccessRule(new FileSystemAccessRule(netAdmin, FileSystemRights.FullControl, InheritanceFlags.ObjectInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
                        acl.SetOwner(netAdmin);

                        di.SetAccessControl(acl);*/

                        string[] firstLvlDirs = Directory.GetDirectories(path);
                        foreach (string sub in firstLvlDirs)
                            goDeeper(sub); //Geht für alle Unterodner durch
                    }


                    //Sollte der Administrator keine Berechtigungen haben, dann...
                    if (!AdminIsIn)
                    {
                        //Vergibt die Berechtigungen an den Netzadmin
                        acl.AddAccessRule(new FileSystemAccessRule(@"...", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
                        acl.AddAccessRule(new FileSystemAccessRule(@"...", FileSystemRights.FullControl, InheritanceFlags.ObjectInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));


                        di.SetAccessControl(acl);

                        //Sammelt alle Unterordner in einer Liste
                        string[] firstLvlDirs = Directory.GetDirectories(path);
                        foreach (string sub in firstLvlDirs)
                            goDeeper(sub); //Geht für alle Unterodner durch

                        //Console.WriteLine("Admin wurden Rechte auf " + path + " gegeben!");
                    }
                    /*else
                        Console.WriteLine("Admin hat Berechtigungen auf " + path);*/
                }
                catch (DirectoryNotFoundException)
                {
                    //Console.WriteLine(path + " wurde nicht gefunden!");
                }
                catch (Exception ex)
                {
                    if(!File.Exists(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt"))
                        File.WriteAllText(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt",
                                        System.DateTime.Now.ToString() + "\n" +
                                        "Fehler beim Vergeben der Rechte!\n\n" + ex.ToString());
                    else
                    {
                        string priorTxt = File.ReadAllText(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt");
                        File.WriteAllText(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt",
                                        priorTxt + "\n\n\n\n" +
                                        System.DateTime.Now.ToString() + "\n" +
                                        "Fehler beim Vergeben der Rechte!\n\n" + ex.ToString());
                    }
                    //Console.WriteLine("Knopf drücken um fortzufahren...");
                    //Console.ReadKey();
                }
            }
            //Console.WriteLine("Knopf drücken um fortzufahren...");
            //Console.ReadKey();
        }

        /// <summary>
        /// Diese Funktion ist rekursiv; Sie vergibt mit addAdmin() Rechte und checkt die Ordner nach Unterordnern. 
        /// Wenn sie welche findet ruft die Funktion sich selbt für die Unterordner auf!
        /// </summary>
        /// <param name="dir">Directorypfad</param>
        static void goDeeper(string dir)
        {
            string[] nextLvlDirs = Directory.GetDirectories(dir);

            addAdmin(dir);

            if(nextLvlDirs.Length != 0)
                foreach (string subDir in nextLvlDirs)
                    goDeeper(subDir);
        }

        /// <summary>
        /// Vergiebt die Zugriffsrechte an den Netzadministrator!
        /// </summary>
        /// <param name="path">Ordnerpfad, der Rechte bekommt</param>
        static void addAdmin(string path)
        {
            try
            {
                DirectoryInfo di = new DirectoryInfo(path);
                DirectorySecurity acl = di.GetAccessControl();
                IdentityReference netAdmin = new NTAccount(@"...");

                acl.AddAccessRule(new FileSystemAccessRule(netAdmin, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
                acl.AddAccessRule(new FileSystemAccessRule(netAdmin, FileSystemRights.FullControl, InheritanceFlags.ObjectInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
                acl.SetOwner(netAdmin);

                di.SetAccessControl(acl);

                Console.WriteLine("Setting " + path);
            }
            catch(Exception exep)
            {
                if (!File.Exists(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt"))
                    File.WriteAllText(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt",
                                       System.DateTime.Now.ToString() + "\n" +
                                       "Fehler beim Vergeben der Rechte bei Unterverzeichnis " + path + "\n\n" + exep.ToString());
                else
                {
                    string priorTxt = File.ReadAllText(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt");
                    File.WriteAllText(@"\\server\ErrorLogs\AdminAccesErrorLog-" + user + ".txt",
                                      priorTxt +"\n\n\n\n" +
                                      System.DateTime.Now.ToString() + "\n" +
                                      "Fehler beim Vergeben der Rechte bei Unterverzeichnis " + path + "\n\n" + exep.ToString());
                }
            }
        }
    }
}
