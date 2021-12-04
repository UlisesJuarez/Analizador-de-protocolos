package main;
import java.util.ArrayList;
import java.util.List;
import java.io.*;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;


public class Proyecto {

    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(':');
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }

        return buf.toString();
    }
    public static long calculateChecksum(byte[] buf) {
    int length = buf.length;
    int i = 0;

    long sum = 0;
    long data;

    // Handle all pairs
    while (length > 1) {
      // Corrected to include @Andy's edits and various comments on Stack Overflow
      data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
      sum += data;
      // 1's complement carry bit correction in 16-bits (detecting sign extension)
      if ((sum & 0xFFFF0000) > 0) {
        sum = sum & 0xFFFF;
        sum += 1;
      }

      i += 2;
      length -= 2;
    }

    // Handle remaining byte in odd length buffers
    if (length > 0) {
      sum += (buf[i] << 8 & 0xFF00);
      if ((sum & 0xFFFF0000) > 0) {
        sum = sum & 0xFFFF;
        sum += 1;
      }
    }

    sum = ~sum;
    sum = sum & 0xFFFF;
    return sum;

  }

    public static void main(String[] args) {
        try {
            Pcap pcap = null;
            Scanner escaner = new Scanner(System.in);
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
            StringBuilder errbuf = new StringBuilder(); // For any error msgs
            System.out.println("[0]-->Realizar captura de paquetes al vuelo");
            System.out.println("[1]-->Cargar traza de captura desde archivo");
            System.out.print("\nElige una de las opciones:");
            int opcion = Integer.parseInt(br.readLine());
            if (opcion == 1) {
                System.out.println("Ingresa el nombre de tu archivo con el formato: nombreArchivo.cap");
                /////////////////////////lee archivo//////////////////////////          
                String fname = escaner.nextLine();
                pcap = Pcap.openOffline(fname, errbuf);
                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: " + errbuf.toString());
                    return;
                }//if
            } else if (opcion == 0) {

                /**
                 * *************************************************************************
                 * First get a list of devices on this system
		 *************************************************************************
                 */
                int r = Pcap.findAllDevs(alldevs, errbuf);
                if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                    System.err.printf("Can't read list of devices, error is %s", errbuf
                            .toString());
                    return;
                }

                System.out.println("Network devices found:");

                int i = 0;
                //try{
                for (PcapIf device : alldevs) {
                    String description
                            = (device.getDescription() != null) ? device.getDescription()
                            : "No description available";
                    final byte[] mac = device.getHardwareAddress();
                    String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
                    System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

                }//for
                System.out.print("\nEscribe el número de interfaz a utilizar:");
                int interfaz = Integer.parseInt(br.readLine());

                PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device
                System.out
                        .printf("\nChoosing '%s' on your behalf:\n",
                                (device.getDescription() != null) ? device.getDescription()
                                : device.getName());

                /**
                 * *************************************************************************
                 * Second we open up the selected device
		 *************************************************************************
                 */
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam mÃ¡x de trama */
                int snaplen = 64 * 1024;           // Capture all packets, no trucation
                int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
                int timeout = 10 * 1000;           // 10 seconds in millis
                pcap
                        = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: "
                            + errbuf.toString());
                    return;
                }//if
            }//else
            /**
             * ******F I L T R O*******
             */
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression = ""; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
            /**
             * *************
             */
            String ofile = "traza_exportada.cap";
            PcapDumper dumper = pcap.dumpOpen(ofile); // output file

            /**
             * *************************************************************************
             * Third we create a packet handler which will receive packets from
             * the libpcap loop.
		 *********************************************************************
             */
            //PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            PcapPacketHandler<PcapDumper> jpacketHandler = new PcapPacketHandler<PcapDumper>() {

                public void nextPacket(PcapPacket packet, PcapDumper dumper) {
                    //public void nextPacket(PcapDumper dumper, long seconds, int useconds,
                    //    int caplen, int len, ByteBuffer buffer) {
                    PcapHeader ph = packet.getCaptureHeader();
                    JBuffer jb = new JBuffer(packet.size());
                    packet.transferTo(jb);
                    dumper.dump(ph, jb);
                    /**
                     * ****Desencapsulado*******
                     */
                    for (int i = 0; i < packet.size(); i++) {
                        System.out.printf("%02X ", packet.getUByte(i));
                        if (i % 16 == 15) {
                            System.out.println("");
                        }
                    }
                     int longitud = (packet.getUByte(12) * 256) + packet.getUByte(13);
                    //Armando el pseudoencabezado
                                //IP Origen
                                    byte[] ip_o = packet.getByteArray(26,4);
                                    
                                //IP Destino
                                    byte[] ip_d = packet.getByteArray(30,4);
                                //Obteniendo la longitud del encabezado de IP
                                    int leip = (packet.getUByte(14)&0x0f)*4;
                                    
                                      byte[] pro= packet.getByteArray(23,1);
                                //Obteniendo la longitud del encapsulado completo
                                    int longitudE = packet.getUByte(16)*256+packet.getUByte(17);
                                //Obteniendo la longitud del PDU de transporte
                                    int lt = longitudE- leip;
                    
                                byte[] longi=packet.getByteArray(16,2);
                                byte[] tramaF=new byte[12+lt];
                                byte[] arrBin=new byte[4];
                                 
                                for(int i=0;i<4;i++)
                                tramaF[i]=ip_o[i];
                                for(int i=0;i<4;i++)
                                tramaF[i+4]=ip_d[i];
                                tramaF[8]=0;
                                tramaF[9]=pro[0];
                                tramaF[10]=longi[0];
                                tramaF[11]=longi[1];
                                long resultado = Proyecto.calculateChecksum(tramaF);
if(longitud<1500){
            System.out.println("\nTrama IEEE802.3");
            System.out.printf("\nMAC Destino: ");
            for(int i=0;i<6;i++)
                System.out.printf("%02x ",packet.getUByte(i));
                System.out.printf("\nMAC Origen: ");
                for(int i=0;i<6;i++)
                    System.out.printf("%02x ",packet.getUByte(i+6));
                    System.out.printf("\nLongitud: %04x ",longitud );
                    System.out.printf("DSAP: %02x ",packet.getUByte(14));
                    System.out.printf("\nSSAP: %02x ",packet.getUByte(15));

                      StringBuilder bin1=new StringBuilder(Integer.toBinaryString(packet.getUByte(16)));
                      StringBuilder bin2=new StringBuilder(Integer.toBinaryString(packet.getUByte(17)));
                      StringBuilder r1,r2,concat,concatRev,a = null,e=null,cadenaBin;
                      String inicio,o;
                         r1=bin1.reverse();
                         r2=bin2.reverse();

                    for(int i=0; r1.length()<8;i++){
                        a= r1.append('0');
                    }
                        for(int i=0; r2.length()<8;i++){
                            e= r2.append('0');
                        }
                            concat=r2.append(r1);
                            cadenaBin=concat.reverse();
//                            System.out.println("\nCadena a trabajar: "+ cadenaBin);
                                                 
                          inicio= cadenaBin.substring(15,16);
                          String ns=cadenaBin.substring(8, 15);
                          String PF=cadenaBin.substring(7,8);
                          String nr=cadenaBin.substring(0,7);
                             
                          int comp=Integer.parseInt(inicio);                                         
                          int comp2=Integer.parseInt(cadenaBin.substring(14, 15));
                          int PFF=Integer.parseInt(PF);

                        String posCod= concat.substring(12,14); //buscar a que codigo pertenece
//                        System.out.println("Valor de posicion de Codigo: "+posCod);
                        String posCodigo= concat.substring(13,15); //buscar a que codigo pertenece                 
                        String acuseR= concat.substring(2,7); //buscar a que codigo pertenece
                                                 
                         if(comp==0){
                            System.out.println("Trama I");                                                                                    
                            convertirBinDecNs(ns);  
                            convertirBinDecNr(nr);
                                                       
                            if(PFF==0){
                                System.out.println("I/G{"+PF+": Individual");
                                System.out.println("C/R{"+PF+": Comando");
                            }else{
                                System.out.println("I/G{"+PF+": Grupal");
                                System.out.println("C/R{"+PF+": Respuesta");    
                            }
                                switch(posCodigo){
                                    case "00":
                                    System.out.println("RR (Listo para recibir)");
                                    break;
                                    case "01":
                                    System.out.println("REJ (Rechazo)");
                                    break;
                                    case "10":
                                    System.out.println("RNR (No listo para recibir)");
                                    break;
                                    case "11":
                                    System.out.println("SREJ (Rechazo Selectivo)");
                                    break;
                                }
                                    switch(acuseR){
                                      case "00001":
                                      System.out.println("SNRM (Normal)");
                                      break;
                                      case "11011":
                                      System.out.println("SNRME (Activado Extendido");
                                      break;
                                      case "11000":
                                      System.out.println("SARM (Modo de Desconexión)");
                                      break;
                                      case "11010":
                                      System.out.println("SARME (Asincrono Extendido)");
                                      break;
                                      case "11100":
                                      System.out.println("SABM (Asincrono Balanceado)");
                                      break;
                                      case "11110":
                                      System.out.println("SABME (Asincrono Balanceado Extendido)");
                                      break;
                                      case "00000":
                                      System.out.println("UT (Información sin numerar)");
                                      break;
                                      case "00110":
                                      System.out.println("- (ACK sin numerar");
                                      break;
                                    }
                                                    
                        }else{
                            if(comp2==0){
                                System.out.println("Trama S");
                                 if(PFF==0){
                                     System.out.println("I/G{"+PF+": Individual");
                                     System.out.println("C/R{"+PF+" 0: Comando");
                                 }else{
                                      System.out.println("I/G{"+PF+": Grupal");
                                      System.out.println("C/R{"+PF+": Respuesta");    
                                 }
                                         //Codigo
                                    switch(posCod){
                                        case "00":
                                        System.out.println("RR (Listo para recibir)");
                                        break;
                                        case "01":
                                        System.out.println("REJ (Rechazo)");
                                        break;
                                        case "10":
                                        System.out.println("RNR (No listo para recibir)");
                                        break;
                                        case "11":
                                        System.out.println("SREJ (Rechazo Selectivo)");
                                        break;
                                        }                   
//                                              N(R)
                                       System.out.println("Convertir a dec Nr: "+ nr);
                                       convertirBinDecNr(nr);
                                                              
                                        switch(acuseR){
                                        case "00001":
                                        System.out.println("SNRM (Normal)");
                                        break;
                                        case "11011":
                                        System.out.println("SNRME (Activado Extendido");
                                        break;
                                        case "11000":
                                        System.out.println("SARM (Modo de Desconexión)");
                                        break;
                                        case "11010":
                                        System.out.println("SARME (Asincrono Extendido)");
                                        break;
                                        case "11100":
                                        System.out.println("SABM (Asincrono Balanceado)");
                                        break;
                                        case "11110":
                                        System.out.println("SABME (Asincrono Balanceado Extendido)");
                                        break;
                                        case "00000":
                                        System.out.println("UT (Información sin numerar)");
                                        break;
                                        case "00110":
                                        System.out.println("- (ACK sin numerar");
                                        break;
                                         }
                                                              
                            }else
                              System.out.println("Trama U");
                              String posCodi= concat.substring(5,7); //buscar a que codigo pertenece
//                              System.out.println("Valor de posicion de Codigo: "+posCodi);
                              if(PFF==0){
                                  System.out.println("I/G{"+PF+": Individual");
                                  System.out.println("C/R{"+PF+" 0: Comando");
                              }else{
                                System.out.println("I/G{"+PF+": Grupal");
                                System.out.println("C/R{"+PF+": Respuesta");    
                                }
                                    switch(posCod){
                                     case "00":
                                     System.out.println("RR (Listo para recibir)");
                                     break;
                                     case "01":
                                     System.out.println("REJ (Rechazo)");
                                     break;
                                     case "10":
                                    System.out.println("RNR (No listo para recibir)");
                                    break;
                                    case "11":
                                     System.out.println("SREJ (Rechazo Selectivo)");
                                    break;
                                    }
                                        switch(posCodi){
                                          case "00":
                                          System.out.println("RR (Listo para recibir)");
                                          break;
                                          case "01":
                                          System.out.println("REJ (Rechazo)");
                                          break;
                                          case "10":
                                          System.out.println("RNR (No listo para recibir)");
                                          break;
                                          case "11":
                                          System.out.println("SREJ (Rechazo Selectivo)");
                                          break;
                                        }
                            }
                                                    
                }   else if (longitud  == 2048) {

                        System.out.println("\nProtcolo IP");
                        // int version = ((packet.getUByte(14)*256) + packet.getUByte(15) + packet.getUByte(16));
                        // System.out.println("Version :"+version);
                        System.out.print("Vesion: ");

                        System.out.printf("%02X: ", packet.getUByte(14));

                        System.out.println("Version 4");
                        // byte IHL = (byte) ((packet.getUByte(17)*256) + packet.getUByte(18) + packet.getUByte(19));

                        System.out.println("4 Indica la version (0100) y el 5 Tamño IHL (0101) 20 BYTES");
                        byte one = packet.getByte(14);
                        System.out.printf("%02X: ", one);

                        byte b1 = (byte) one;
                        String s1 = String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);

                        System.out.println("Longitud Total: ");
                        int servicio2 = (packet.getUByte(16) * 256) + packet.getUByte(17);
                        byte servicio = (byte) (packet.getByte(16) + packet.getByte(17));
                        System.out.printf("HEX %02X: ", servicio2);
                        System.out.print(" INT " + servicio2 + " :");
                        b1 = (byte) servicio;
                        s1 = String.format(" %8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);

                        System.out.println("Identificador: ");
                        int ident2 = (packet.getUByte(18) * 256) + packet.getUByte(19);
                        byte indet = (byte) (packet.getByte(18) + packet.getByte(19));
                        System.out.printf("HEX %02X: ", ident2);
                        System.out.print(" INT " + ident2 + " :");
                        b1 = (byte) indet;
                        s1 = String.format(" %8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);

                        System.out.println("FLAGS ");
                        byte flag = (byte) (packet.getByte(20));
                        b1 = (byte) flag;
                        s1 = String.format(" %8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);
                        char caracter;
                        char a[] = new char[3];
                        for (int i = 0; i < a.length; i++) {
                            a[i] = s1.charAt(i);
                            System.out.print(a[i] + " ");
                        }
                        System.out.println("\nPaquete Fragmentado: ");
                        byte frag = (byte) (+packet.getByte(21));
                        char b[] = new char[13];
                        b1 = (byte) frag;
                        s1 = String.format(" %16s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);

                        int j = 0;
                        for (int i = 0; i < b.length; i++) {
                            b[j] = s1.charAt(i);
                            System.out.print(b[j] + " ");
                            j++;
                        }

                        System.out.println("\nTime to live / Tiempo de Vida");
                        byte Time_Protocolo = packet.getByte(22);
                        int time = packet.getUByte(22);
                        System.out.printf("HEX %02X: ", time);
                        System.out.print(" INT " + time + " :");
                        b1 = (byte) Time_Protocolo;
                        s1 = String.format(" %8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);

                        int protocolo = packet.getUByte(23);
                        System.out.println("Codigo de Protocolo: " + protocolo);
                        if (protocolo == 1) {
                            System.out.println("ICMP");
                            int ihl = 5;
                            int posicionInicial = 14 + (ihl * 4);
                            int PrimerByte = posicionInicial + 8;
                            int tipo_ICMP = packet.getUByte(PrimerByte);
                            int codigo_ICMP = packet.getByte(PrimerByte + 8);

                            switch (tipo_ICMP) {
                                case 0:
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Echo Reply");
                                    System.out.println("Codigo debe ser cero: " + codigo_ICMP);
                                    break;

                                case 3:
                                    System.out.println("Tipo: " + tipo_ICMP + " Destination Unreachable");
                                    switch (codigo_ICMP) {
                                        case 0:
                                            System.out.println("Network unreachable");
                                            break;
                                        case 1:
                                            System.out.println("Host unreachable");
                                            break;
                                        case 2:
                                            System.out.println("Protocol unreachable");
                                            break;
                                        case 3:
                                            System.out.println("Port unreachable");
                                            break;
                                        case 4:
                                            System.out.println("Fragmentation needed, but do not fragment bit set");
                                            break;
                                        case 5:
                                            System.out.println("Source route failed");
                                            break;
                                        case 6:
                                            System.out.println("Destination network unknown");
                                            break;
                                        case 7:
                                            System.out.println("Destination host unknown");
                                            break;
                                        case 8:
                                            System.out.println("Source host isolated error (military use only)");
                                            break;
                                        case 9:
                                            System.out.println("The destination network is administratively prohibite");
                                            break;
                                        case 10:
                                            System.out.println("The destination host is administratively prohibited");
                                            break;
                                        case 11:
                                            System.out.println("The network is unreachable for Type Of Service");
                                            break;

                                        case 12:
                                            System.out.println("The host is unreachable for Type Of Service");
                                            break;
                                        case 13:
                                            System.out.println("Communication administratively prohibited (administrative filtering prevents packet from being forwarded)");

                                            break;
                                        case 14:
                                            System.out.println("Host precedence violation (indicates the requested precedence is not permitted for the combination of host or network and port)");

                                            break;
                                        case 15:
                                            System.out.println("Precedence cutoff in effect (precedence of datagram is below the level set by the network administrators)");
                                            break;

                                    }
                                    break;

                                case 4:
                                    System.out.println("Fuente Saciable");
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Fuente Saciable");
                                    System.out.println("Codigo debe ser cero: " + codigo_ICMP);
                                    break;

                                case 5:
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Redirecciones");
                                    switch (codigo_ICMP) {
                                        case 0:
                                            System.out.println("Redirección de la Red");
                                            break;
                                        case 1:
                                            System.out.println("edirección para el Host");
                                            break;

                                        case 2:
                                            System.out.println("Redirección del Tipo de Servicio y de Red");
                                            break;

                                        case 3:
                                            System.out.println("Redirección para el Tipo de Servicio y el Host");
                                            break;

                                    }
                                    break;

                                case 8:
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Echo Request");
                                    System.out.println("Codigo debe ser cero: " + codigo_ICMP);
                                    break;

                                case 11:
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Tiempo extendido");
                                    if (codigo_ICMP == 0) {
                                        System.out.println("Tiempo de Vida excedio  en ek transito");
                                    } else {
                                        System.out.println("Tiempo de vida excedido ene l fragmento");
                                    }
                                    break;

                                case 13:
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Timestamp");
                                    System.out.println("Codigo debe ser cero: " + codigo_ICMP);
                                    break;
                                    
                                    
                                case 14:
                                    System.out.println("Tipo:  " + tipo_ICMP + "  Respuesta Timestamp");
                                    System.out.println("Codigo debe ser cero: " + codigo_ICMP);
                                  break;

                            }

                        }
                        
                        System.out.println("Checksum");
                        byte checksum = (byte) (packet.getByte(24) + packet.getByte(25));
                        int check = packet.getUByte(24) + packet.getUByte(25);
                        System.out.printf("HEX %02X: ", check);
                        System.out.print(" INT " + check + " :");
                        b1 = (byte) checksum;
                        s1 = String.format(" %16s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                        System.out.println(s1);

                        System.out.println("IP Origen");
                        for (int i = 26; i < 30; i++) {
                            //System.out.printf("%02X: ", packet.getUByte(i));
                            System.out.print(packet.getUByte(i) + " : ");
                        }

                        System.out.println("\nIP Destino");
                        for (int i = 30; i < 34; i++) {
                            // System.out.printf("%02X: ", packet.getUByte(i));
                            System.out.print(packet.getUByte(i) + " : ");
                        }

                    }if (longitud==2054){
                        System.out.println("Protocolo ARP");
                        System.out.println("Tipo: 2054");
                        
                        System.out.println("\nLongitud de Dirección de Hardware");
                        for (int i = 14; i < 15; i++) {
                            System.out.printf("%02X ", packet.getUByte(i));
                        }
                         System.out.println("\nLongitud Protocolo");
                        for (int i = 15; i < 16; i++) {
                            System.out.printf("%02X ", packet.getUByte(i));
                        }
//                        int LDH= packet.getUByte(18)*256;
//                        System.out.println("Longitud de Direccion de Hardware: "+ LDH);
//                        
//                        int LP=packet.getUByte(19)*256;
//                        System.out.println("Longitud de Protocolo: "+ LP);
//                        
//                        
                         int operacion=packet.getUByte(20)*256+packet.getUByte(21);
                            System.out.println("\nOperacion "+operacion);
                        switch(operacion){
                            case 1: 
                                System.out.println("ARP: Request");
                                break;
                            case 2: 
                                System.out.println("ARP: Response");
                                break;
                        }
                        
                        System.out.println("\nMAC Emisor");
                        for (int i = 22; i < 28; i++) {
                            System.out.printf("%02X ", packet.getUByte(i));
                        }
                        
                        System.out.println("\nIP Emisor");
                        for (int i = 28; i < 32; i++) {
                            System.out.printf("%02X ", packet.getUByte(i));
                        }
                        
                        System.out.println("\nMAC Destino");
                        for (int i = 32; i < 38; i++) {
                            System.out.printf("%02X ", packet.getUByte(i));
                        }
                        
                        System.out.println("\nIP Destino");
                        for (int i = 38; i < 42; i++) {
                            System.out.printf("%02X ", packet.getUByte(i));
                        }
                        
                        System.out.println("");
                        
                        
                        
                    }                  
                }                
                public int convertirBinDecNs(String ns){
                              int n= Integer.valueOf( ns,2);
                              System.out.println("El valor de N(s) es: "+ n);
                              return n;        
                       } 
                       public int convertirBinDecNr(String ns){
                              int n= Integer.valueOf( ns,2);
                              System.out.println("El valor de N(r) es: "+ n);
                              return n;        
                       }  

                        
                        
                       
                       

                /*  @Override
                    public void nextPacket(PcapPacket packet, PcapDumper user) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                 */            };

            /**
             * *************************************************************************
             * Fourth we enter the loop and tell it to capture 10 packets. The
             * loop method does a mapping of pcap.datalink() DLT value to
             * JProtocol ID, which is needed by JScanner. The scanner scans the
             * packet buffer and decodes the headers. The mapping is done
             * automatically, although a variation on the loop method exists
             * that allows the programmer to sepecify exactly which protocol ID
             * to use as the data link type for this pcap interface.
		 *************************************************************************
             */
            pcap.loop(100, jpacketHandler, dumper);

            /**
             * *************************************************************************
             * Last thing to do is close the pcap handle
		 *************************************************************************
             */
            dumper.close();
            pcap.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
     //bit poll/final(p/f)  |   bit sondeo/fin -----> se indica solamente si esta encendido
    private static void pollFinal(String c_r, int byteRecibido, String version) {
        String p_f = "";
        if (version.equals("Extendida")) {
            if ((c_r.equals("Comando")) == true) {
                p_f = ((byteRecibido & 0x00000001) == 1) ? "P" : "";
                System.out.printf("\n |-->Bit(p/f):  %s", p_f);
            } else if ((c_r.equals("Respuesta")) == true) {
                p_f = ((byteRecibido & 0x00000001) == 1) ? "F" : "";
                System.out.printf("\n |-->Bit(p/f): %s", p_f);
            }
        } else if (version.equals("Reducida")) {

            if ((c_r.equals("Comando")) == true) {
                p_f = (((byteRecibido >> 4) & 0x0001) == 1) ? "P" : "";
                System.out.printf("\n |-->Bit(p/f):  %s\n", p_f);
            } else if ((c_r.equals("Respuesta")) == true) {
                p_f = (((byteRecibido >> 4) & 0x0001) == 1) ? "F" : "";
                System.out.printf("\n |-->Bit(p/f): %s\n", p_f);
            }
        }
    }

    //Numero de secuencia N(s): Cuenta la secuencia de tramas transmitidas (send). 
    private static void numeroSecuencia(int primerByte, String version) {
        int n_s = primerByte >> 1;//& 0x1111111
        if (version.equals("Extendida")) {
            System.out.printf(" |-->Numero de secuencia N(s) version %s:\n\tDecimal: %d \tHexadecimal: %02X", version, n_s, n_s);
        } else if (version.equals("Reducida")) {
            n_s = primerByte & 0x0000111;
            System.out.printf(" |-->Numero de secuencia N(s) version %s:\n\tDecimal: %d \tHexadecimal: %02X", version, n_s, n_s);
        }

    }

    /*Numero de acuse N(r): da el número (Ns) de la trama que la estación que transmite espera recibir.
        tambien conocido como: numero de secuencia de recepcion*/
    private static void numeroAcuse(int byteRecibido, String version) {
        int n_r = byteRecibido >> 1; //& 0x1111111
        if (version.equals("Extendida")) {
            System.out.printf("\n |-->Numero de acuse/recivo version: %s N(r):\n\tDecimal: %d \tHexadecimal: %02X", version, n_r, n_r);
        } else if (version.equals("Reducida")) {
            n_r = byteRecibido >> 4;
            System.out.printf("\n |-->Numero de acuse/recivo version: %s N(r):\n\tDecimal: %d \tHexadecimal: %02X", version, n_r, n_r);
        }
    }

    // Funcion para invertir los bits de un numero entero
    public static int reverseBits(int number) {
        int res = 0;
        System.out.println(">> Byte recibido sin agregar ceros: " + Integer.toBinaryString(number));
        /*Llama a la funcion "addZeros" para poder ser invertida de manera correcta
          de lo contrario no toma en cuenta el primer cero
        A la funcion se le manda el numero como una cadena de bits
         */
        String cadenaTemporal = addZeros(Integer.toBinaryString(number));
        System.out.println(">> Byte recibido con ceros agregados: " + cadenaTemporal);
        //cambia el orden de la cadena, ordena de derecha a izquierda
        String cadenaEnviar = new StringBuilder(cadenaTemporal).reverse().toString();
        System.out.println(">> Byte invertido para analizar: " + cadenaEnviar);
        //Convierte la cadena de bits a un numero entero y lo envia
        res = Integer.parseInt(cadenaEnviar, 2);
        return res;
    }

    //Funcion para agregar cero a la izquierda para poder invertirlo 
    private static String addZeros(String number) {
        //Declaracion de variables
        int i = 0;
        String temp = "";
        //Si la longitud no es de un multiplo de 2 se le agrega un cero
        if (i < 2 - (number.length() % 2)) {
            temp += "0";
        }
        /*A los ceros concatenados en el if anterior se le va a concatenar
        la cadena de bits, si se hace al reves esta mal trabajado
         */
        temp += number;
        //se envia la cadena final
        return temp;
    }
    
}
