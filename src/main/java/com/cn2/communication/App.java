package com.cn2.communication;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.Semaphore;

import javax.crypto.Cipher;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.DataLine;
import javax.sound.sampled.SourceDataLine;
import javax.sound.sampled.TargetDataLine;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * Simple application created for the CN2 course.
 * Authors: Lamprinos Chatziioannou, Sokratis Nazlidis
 */
public class App extends Frame implements WindowListener, ActionListener {

    // ********************************************************************************
    // CONSTANTS
    // ********************************************************************************
    /** Default IP address for the server. */
    private static final String STARTING_IP = "127.0.0.1";

    /** Port number for chat communication. */
    private static final int CHAT_PORT = 6969;

    /** Port number for VOIP communication. */
    private static final int VOIP_PORT = 6970;

    /** Buffer size (in bytes) for incoming and outgoing data. */
    private static final int BUFFER_SIZE = 1024;

    /** Number of rows in the chat UI. */
    private static final int CHAT_ROWS = 200;

    /** Number of columns in the chat UI. */
    private static final int CHAT_COLS = 600;

    /** Prefix for log information messages. */
    private static final String INFO_STRING = "[INFO]";

    /** Default log length for displaying in the GUI. */
    private static final int INFO_LENGTH = 65;

    /** Audio sample rate in Hz (telephony standard). */
    private static final float AUDIO_SAMPLE_RATE = 8000.0f;

    /** Number of bits per audio sample. */
    private static final int AUDIO_SAMPLE_SIZE = 8;

    /** Number of audio channels (1 for mono). */
    private static final int AUDIO_CHANNELS = 1;

    /** Indicates whether the audio data is signed. */
    private static final boolean AUDIO_SIGNED = true;

    /** Indicates whether the audio uses big-endian byte order. */
    private static final boolean AUDIO_BIGENDIAN = true;

    // ********************************************************************************
    // Class Variables
    // ********************************************************************************

    // UI Elements
    /** Input field for typing messages. */
    private JTextField inputTextField;

    /** Input field for entering the remote IP address. */
    private JTextField ipTextField;

    /** Button to send a message. */
    private JButton sendButton;

    /** Button to initiate a VOIP call. */
    private JButton callButton;

    /** Button to change the remote IP address. */
    private JButton changeRemoteIPButton;

    /** Checkbox to toggle encryption on or off. */
    private JCheckBox encryptionToggle;

    /** Checkbox to enable or disable debug mode. */
    private JCheckBox debugToggle;

    /** Pane to display chat messages. */
    private JTextPane textPane;

    /** Styled document for customizing text styles in the chat. */
    private StyledDocument doc;

    /** Style for incoming messages. */
    private SimpleAttributeSet incomingMsgStyle;

    /** Style for outgoing messages. */
    private SimpleAttributeSet outgoingMsgStyle;

    /** Style for informational messages. */
    private SimpleAttributeSet infoStyle;

    /** Style for message source labels. */
    private SimpleAttributeSet msgSourceStyle;

    /** Style for message timestamps. */
    private SimpleAttributeSet msgTimeStyle;

    /** Remote IP address used for communication. */
    private InetAddress remoteIP;

    /** Datagram socket for chat communication. */
    private DatagramSocket chatSocket;

    /** Datagram socket for VOIP communication. */
    private DatagramSocket voipSocket;

    /** Thread for listening to incoming chat messages. */
    private Thread chatListenerThread;

    /** Thread for listening to incoming VOIP data. */
    private Thread voipListenerThread;

    /** Semaphore to ensure sequential execution of message display operations. */
    final private Semaphore msgSemaphore = new Semaphore(1);

    /** RSA key pair for encryption and decryption. */
    private KeyPair keyPair;

    /** Stores remote public keys mapped to their respective IP addresses. */
    private HashMap<InetAddress, PublicKey> remotePublicKeys = new HashMap<>();

    /**
     * Constructs the application with the specified title.
     * Initializes the user interface and network sockets.
     *
     * @param title The title of the application window.
     */
    public App(String title) {
        super(title);
        initializeUI();
        initializeSockets();
    }

    /**
     * Initializes the Datagram sockets for chat and VOIP communication.
     * Sets up sockets on predefined ports and updates the socket state.
     * In case of failure, an error message is displayed.
     */
    private void initializeSockets() {
        try {
            chatSocket = new DatagramSocket(CHAT_PORT);
            voipSocket = new DatagramSocket(VOIP_PORT);
            printDebug("Sockets initialized");
        } catch (Exception e) {
            showError("Error initializing sockets: " + e.getMessage());
        }
    }

    /**
     * Connects to the specified server IP address and initializes communication.
     * Resolves the given address, sends the public key, and starts listening if
     * not already active. Handles invalid IP addresses gracefully by retaining
     * the previous value.
     *
     * @param newAddress The IP address of the server to connect to.
     */
    private void connectToServer(InetAddress newAddress) {
        remoteIP = newAddress;
        printDebug("Sending to " + newAddress.getHostAddress());
        sendPublicKey();
        startListening(); // handles resource mgmt inside
    }

    /**
     * Starts two threads to listen for incoming chat messages and VOIP data
     * simultaneously.
     * One thread handles chat messages, decrypting and displaying them, while the
     * other
     * processes incoming voice data for playback. Updates the socket listening
     * state.
     * Errors during reception are handled and logged appropriately.
     */
    private void startListening() {
        if (!chatListenerThread.isAlive())
            chatListenerThread.start();

        if (!voipListenerThread.isAlive())
            voipListenerThread.start();
    }

    /**
     * Buffers the message into chunks of a maximum size specified by BUFFER_SIZE or
     * 190, in case the message is to be encrypted (Necessary due to the
     * selected encryption algorithm).
     *
     * @param message The original message to be buffered.
     * @return An array of strings, where each string is a chunk of the original
     *         message.
     */
    private String[] bufferMessage(String message) {
        byte[] messageBytes = message.getBytes();
        int totalLength = messageBytes.length;
        // chunkSize might be limited by the RSA encryption
        int chunkSize = (encryptionToggle.isSelected()) ? 190 : BUFFER_SIZE;
        int chunkCount = (int) Math.ceil((double) totalLength / chunkSize);
        if (chunkCount > 1)
            printDebug("Message will necessarily split into " + chunkCount +
                    ", " + chunkSize + " byte long, chunks.");

        String[] bufferedMessages = new String[chunkCount];
        for (int i = 0; i < chunkCount; i++) {
            int offset = i * chunkSize;
            int length = Math.min(chunkSize, totalLength - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(messageBytes, offset, chunk, 0, length);
            bufferedMessages[i] = new String(chunk);
        }
        return bufferedMessages;
    }

    /**
     * Sends a message to the remote IP address through the chat socket.
     * If encryption is enabled, the message is encrypted before sending.
     * If encryption is disabled, a warning is displayed to confirm unencrypted
     * communication.
     * The original message is displayed in the chat window after sending.
     *
     * Handles any errors encountered during message transmission.
     */
    private void sendMessage() {
        String message = inputTextField.getText();

        // Handle cases in which message is too long
        String[] bufferedMessages = bufferMessage(message);

        // Handle encryption
        String[] finalMessage = encryptMessages(bufferedMessages);

        try {
            for (String chunk : finalMessage) {
                byte[] buffer = chunk.getBytes();
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length,
                        remoteIP, CHAT_PORT);
                chatSocket.send(packet);
                printDebug("Packet sent to " + remoteIP.getHostName());
            }
            showMessage("localhost", message, outgoingMsgStyle); // Display the original message
        } catch (Exception sendException) {
            showError("Failed to send the message: " + sendException.getMessage());
        }
    }

    /**
     * Starts a Voice over IP (VOIP) call by capturing audio input from the
     * microphone
     * and sending it as UDP packets over the network.
     *
     * Key features:
     * - Uses 8kHz sample rate, 16-bit audio, mono channel.
     * - Sends audio packets to a predefined remote IP and port.
     * - Configures UDP socket with Expedited Forwarding QoS for prioritization.
     */
    private void startCall() {
        // Start a new thread for capturing and sending audio data.
        new Thread(() -> {
            try {
                // Configure the audio format for the microphone.
                AudioFormat format = new AudioFormat(AUDIO_SAMPLE_RATE, AUDIO_SAMPLE_SIZE,
                        AUDIO_CHANNELS, AUDIO_SIGNED, AUDIO_BIGENDIAN);

                // Obtain the microphone line with the specified audio format.
                TargetDataLine microphone = (TargetDataLine) AudioSystem.getLine(
                        new DataLine.Info(TargetDataLine.class, format));

                // Open and start the microphone line for capturing audio.
                microphone.open(format);
                microphone.start();

                // Notify the user that the call has started.
                showInfoMessage("CALL STARTED");

                // Configure the DatagramSocket to send voice packets.
                voipSocket.setTrafficClass(
                        0x28); // Set high-priority QoS (Expedited Forwarding)

                byte[] buffer = new byte[BUFFER_SIZE]; // Buffer to hold audio data.

                while (true) { // Continuous loop for capturing and sending audio.
                    // Read audio data into the buffer from the microphone.
                    int bytesRead = microphone.read(buffer, 0, buffer.length);

                    if (bytesRead > 0) { // Only send data if bytes are read.
                        // Create a DatagramPacket with the captured audio data.
                        DatagramPacket voicePacket = new DatagramPacket(buffer, bytesRead, remoteIP, VOIP_PORT);

                        // Send the voice packet over the socket.
                        voipSocket.send(voicePacket);
                    }
                }
            } catch (Exception e) {
                // Handle exceptions and display an error message to the user.
                showError("Error during VOIP call: " + e.getMessage());
            }
        }).start(); // Start the thread for the call.
    }

    /**
     * Updates the remote IP address and resets the connection.
     * Checks if the new user supplied IP string is a valid one, and if it differs
     * from the current one. If both checks pass, it reconnects to the server.
     *
     * @param inputIP User supplied string, if properly used, in the form of an
     *                address or a hostname
     */
    private void changeRemoteIP(String inputIP) {
        try {
            InetAddress newIP = InetAddress.getByName(inputIP);

            if (remoteIP == null || !remoteIP.equals(newIP)) {
                connectToServer(newIP);
                if (remotePublicKeys.containsKey(remoteIP)) {
                    encryptionToggle.setSelected(true);
                } else
                    encryptionToggle.setSelected(false);
            }
        } catch (UnknownHostException e) {
            showError("Invalid IP address. It will not be taken into "
                    + "consideration. Using previous value");
            ipTextField.setText(remoteIP != null ? remoteIP.getHostAddress() : "");
        }
    }

    /**
     * The main entry point of the application.
     * Initializes the application, sets up the UI, RSA keys, and starts listener
     * threads
     * for chat messages and VOIP data.
     *
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {
        App app = new App("CN2 - A.U.Th.");
        app.setSize(500, 250);
        app.setVisible(true);
        app.generateRSAKeys();

        // Thread for listening to chat messages
        app.chatListenerThread = new Thread(() -> {
            byte[] buffer = new byte[BUFFER_SIZE];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

            while (true) {
                try {
                    app.chatSocket.receive(packet);
                    app.printDebug("Chat packet received");
                    String message = app.decryptMessage(packet);
                    String source = packet.getAddress().getHostName();
                    app.showMessage(source, message, app.incomingMsgStyle);
                } catch (Exception e) {
                    app.showError("Error receiving message: " + e.getMessage());
                }
            }
        });

        // Thread for listening to VOIP data
        app.voipListenerThread = new Thread(() -> {
            try {
                AudioFormat format = new AudioFormat(AUDIO_SAMPLE_RATE, AUDIO_SAMPLE_SIZE,
                        AUDIO_CHANNELS, AUDIO_SIGNED, AUDIO_BIGENDIAN);
                SourceDataLine speaker = (SourceDataLine) AudioSystem.getLine(
                        new DataLine.Info(SourceDataLine.class, format));
                speaker.open(format);
                speaker.start();

                app.printDebug("VOIP thread started.");

                byte[] buffer = new byte[BUFFER_SIZE];
                DatagramPacket voicePacket = new DatagramPacket(buffer, buffer.length);

                while (true) {
                    app.voipSocket.receive(voicePacket);
                    speaker.write(voicePacket.getData(), 0, voicePacket.getLength());
                }
            } catch (Exception e) {
                app.showError("Error receiving VOIP: " + e.getMessage());
            }
        });

        // Set initial remote IP
        app.changeRemoteIP(STARTING_IP);
    }

    // ********************************************************************************
    // Uniform Output
    // ********************************************************************************

    /**
     * Prints a debug message to the CLI if debug mode is enabled.
     *
     * @param content The debug message to be printed.
     */
    private void printDebug(String content) {
        if (debugToggle.isSelected())
            System.err.printf("[DEBUG]\t %s\n", content);
    }

    /**
     * Prints an error message to the CLI in red text.
     *
     * @param content The error message to be printed.
     */
    private void printError(String content) {
        System.err.printf("%s[ERROR]\t %s%s\n", "\u001B[31m", content, "\u001B[0m");
    }

    /**
     * Displays an error message in a popup UI window and logs it in the CLI.
     *
     * @param message The error message to be displayed.
     */
    private void showError(String message) {
        printError(message);
        JOptionPane.showMessageDialog(this, message, "Error",
                JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Displays an informational message with a uniform style in the chat window.
     *
     * @param message The informational message to be displayed.
     */
    private void showInfoMessage(String message) {
        String asterisks = "*".repeat((INFO_LENGTH - message.length()) / 2);
        showMessage(INFO_STRING, asterisks + " " + message + " " + asterisks,
                incomingMsgStyle);
    }

    /**
     * Displays a formatted message in the chat UI, ensuring thread-safe
     * insertion. Includes a timestamp, source, encryption indicator, and message
     * styling.
     *
     * @param source       The source of the message (e.g., sender).
     * @param message      The content of the message.
     * @param messageStyle The style attributes to be applied to the message.
     * @param isEncrypted  Indicates whether the message is encrypted.
     */
    private void showMessage(String source, String message,
            SimpleAttributeSet messageStyle,
            boolean isEncrypted) {
        if (message != null && message.length() > 0) {
            try {
                msgSemaphore.acquire();
                doc.insertString(doc.getLength(),
                        "[" +
                                LocalDateTime.now().format(
                                        DateTimeFormatter.ofPattern("HH:mm:ss"))
                                +
                                "]\t",
                        msgTimeStyle);
                doc.insertString(doc.getLength(), (isEncrypted ? "enc " : "--- "),
                        infoStyle);
                doc.insertString(
                        doc.getLength(), source + "\t",
                        (source.equals(INFO_STRING) ? infoStyle : msgSourceStyle));
                doc.insertString(doc.getLength(), message + '\n', messageStyle);
            } catch (Exception e) {
                printError(e.getMessage());
            } finally {
                msgSemaphore.release();
            }
        }
    }

    /**
     * Overloaded method to display a message with default encryption behavior.
     *
     * @param source       The source of the message.
     * @param message      The content of the message.
     * @param messageStyle The style attributes to be applied to the message.
     */
    private void showMessage(String source, String message,
            SimpleAttributeSet messageStyle) {
        showMessage(source, message, messageStyle, encryptionToggle.isSelected());
    }
    // ********************************************************************************
    // Encryption
    // ********************************************************************************

    /**
     * Generates an RSA key pair for encryption and decryption.
     * Uses a key length of 2048 bits for secure communication.
     * Displays an error message if the RSA algorithm is not available.
     */
    private void generateRSAKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); // key length: 2048 bits
            keyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            showError("No such algorithm: encryption error.");
        }
    }

    /**
     * Sends the RSA public key to a specified remote host.
     * The public key is encoded in Base64 format and sent as a Datagram packet.
     * This method allows encrypted communication with multiple hosts.
     * Displays a debug message on success or an error message on failure.
     *
     * @param remoteHost The IP address to which the public key will be sent.
     */
    private void sendPublicKey(InetAddress remoteHost) {
        try {
            String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            byte[] buffer = publicKeyString.getBytes();
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, remoteHost, CHAT_PORT);
            chatSocket.send(packet);

            printDebug("Public key sent to " + remoteHost.getHostName());
        } catch (Exception e) {
            showError("Error sending public key: " + e.getMessage());
        }
    }

    /**
     * Sends the RSA public key to the default remote IP address.
     * This method calls the overloaded version to handle the transmission.
     */
    private void sendPublicKey() {
        sendPublicKey(remoteIP);
    }

    /**
     * Processes and sets the received RSA public key.
     * Decodes the received Base64-encoded public key string, converts it into an
     * RSA public key,
     * and enables encryption by toggling the encryption option.
     * Displays a confirmation message upon success or an error message if the
     * operation fails.
     *
     * @param receivedData The Base64-encoded RSA public key received from the
     *                     remote host.
     * @param address      The remote host address, (who sent their PublicKey)
     */

    private void receivePublicKey(InetAddress address, String receivedData) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(receivedData);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            PublicKey receivedKey = keyFactory.generatePublic(spec);

            // Check if a key already exists for this address
            PublicKey existingKey = remotePublicKeys.get(address);
            if (existingKey == null ||
                    existingKey.getEncoded() == receivedKey.getEncoded()) {
                // If the key does not exist or is different, store the new key and
                // respond
                remotePublicKeys.put(address, receivedKey);
                sendPublicKey(address);
                printDebug("Public key received " + address);
            }

            showInfoMessage("Key pair set for: " + address);
            encryptionToggle.setSelected(true);
        } catch (Exception e) {
            showError("Error processing received public key: " + e.getMessage());
        }
    }

    /**
     * Encrypts a message using the remote public RSA key.
     * Utilizes the "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" algorithm for secure
     * encryption.
     * The encrypted message is returned as a Base64-encoded string.
     *
     * If the remote public key is not set, an exception is thrown and an error is
     * displayed.
     *
     * @param message The plaintext message to be encrypted.
     * @return The encrypted message as a Base64-encoded string, or null if
     *         encryption fails.
     */
    private String encryptMessage(String message) {
        try {
            if (!remotePublicKeys.containsKey(remoteIP)) {
                throw new IllegalStateException("Remote public key is not set.");
            }

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, remotePublicKeys.get(remoteIP));
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            showError("Problem encrypting message: " + e.getMessage());
            return null;
        }
    }

    /**
     * Encrypts an array of messages.
     *
     * @param messages The array of plaintext messages to be encrypted.
     * @return An array of encrypted messages as Base64-encoded strings. If
     *         encryption
     *         of a particular message fails, null is added for that message.
     */
    private String[] encryptMessages(String[] messages) {
        if (encryptionToggle.isSelected() &&
                remotePublicKeys.containsKey(remoteIP)) {

            String[] encryptedMessages = new String[messages.length];
            for (int i = 0; i < messages.length; i++) {
                encryptedMessages[i] = encryptMessage(messages[i]);
            }
            return encryptedMessages;
        } else {
            int option = JOptionPane.showConfirmDialog(
                    this,
                    "Warning: Your message will be sent unencrypted. Do you wish to proceed?",
                    "Unencrypted Communication", JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);

            if (option == JOptionPane.NO_OPTION) {
                return null;
            }
            return messages;
        }
    }

    /**
     * Decrypts an encrypted message using the private RSA key.
     * If encryption is disabled, the original encrypted data is returned.
     * Handles public key exchange when the data indicates a public key.
     *
     * Utilizes the "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" algorithm for
     * decryption.
     *
     * @param incomingPacket The encrypted message or public key data.
     * @return The decrypted message as plaintext, or a confirmation of public key
     *         exchange.
     * @throws Exception If decryption fails or key pair is not properly set.
     */
    private String decryptMessage(DatagramPacket incomingPacket)
            throws Exception {

        // It does not matter if encryption is selected. We have received a public
        // key.x
        String receivedData = new String(incomingPacket.getData(), 0, incomingPacket.getLength());

        if (receivedData.startsWith("MIIB")) {
            receivePublicKey(incomingPacket.getAddress(), receivedData);
            return null;
        }

        if (!encryptionToggle.isSelected()) {
            return receivedData;
        }

        if (keyPair == null) {
            throw new IllegalStateException("Key pair is not set.");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] decodedBytes = Base64.getDecoder().decode(receivedData);
        return new String(cipher.doFinal(decodedBytes));
    }

    // ********************************************************************************
    // Standard UI - In large, untouched
    // ********************************************************************************
    /**
     * Initializes the user interface (UI) components for the application.
     * Sets up the layout, input fields, buttons, checkboxes, and a scrollable
     * chat pane with custom message styles.
     */
    private void initializeUI() {
        setBackground(new Color(254, 254, 254));
        setLayout(new FlowLayout());
        addWindowListener(this);

        inputTextField = new JTextField("Hello!", 20);
        ipTextField = new JTextField(STARTING_IP, 15); // IP input field

        // Chat display pane with basic word wrapping customization
        JTextPane textPane = new JTextPane() {
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return true;
            }
        };
        textPane.setPreferredSize(new Dimension(CHAT_COLS, CHAT_ROWS));
        textPane.setEditable(false);
        doc = textPane.getStyledDocument();

        // Message styles
        incomingMsgStyle = new SimpleAttributeSet();
        StyleConstants.setBold(incomingMsgStyle, true);

        outgoingMsgStyle = new SimpleAttributeSet();

        infoStyle = new SimpleAttributeSet();
        StyleConstants.setForeground(infoStyle, new Color(255, 0, 0));

        msgSourceStyle = new SimpleAttributeSet();
        StyleConstants.setBold(msgSourceStyle, true);
        StyleConstants.setForeground(msgSourceStyle, new Color(86, 158, 30));

        msgTimeStyle = new SimpleAttributeSet();
        StyleConstants.setItalic(msgTimeStyle, true);

        // Scrollable text area setup
        JScrollPane scrollPane = new JScrollPane(textPane);
        scrollPane.setVerticalScrollBarPolicy(
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setAutoscrolls(false);
        scrollPane.setSize(CHAT_COLS, CHAT_ROWS);

        // Buttons and checkboxes
        sendButton = new JButton("Send");
        callButton = new JButton("Call");
        changeRemoteIPButton = new JButton("Use new IP Address");

        encryptionToggle = new JCheckBox("Encrypt Messages");
        encryptionToggle.setSelected(false);

        debugToggle = new JCheckBox("CLI Debug");
        debugToggle.setSelected(false);

        // Add components to the UI
        add(scrollPane);
        add(inputTextField);
        add(sendButton);
        add(callButton);
        add(ipTextField);
        add(changeRemoteIPButton);
        add(encryptionToggle);
        add(debugToggle);

        // Action listeners for buttons
        sendButton.addActionListener(this);
        callButton.addActionListener(this);
        changeRemoteIPButton.addActionListener(this);
    }

    /**
     * Handles button click events triggered in the UI.
     * Identifies the source of the event and executes the corresponding function.
     *
     * @param event The ActionEvent triggered by a button press.
     */
    @Override
    public void actionPerformed(ActionEvent event) {
        Object source = event.getSource();

        if (source == sendButton) {
            sendMessage();
        } else if (source == callButton) {
            startCall();
        } else if (source == changeRemoteIPButton) {
            changeRemoteIP(ipTextField.getText());
        }
    }

    @Override
    public void windowActivated(WindowEvent e) {
    }

    @Override
    public void windowClosed(WindowEvent e) {
    }

    @Override
    public void windowClosing(WindowEvent e) {
        dispose();
        System.exit(0);
    }

    @Override
    public void windowDeactivated(WindowEvent e) {
    }

    @Override
    public void windowDeiconified(WindowEvent e) {
    }

    @Override
    public void windowIconified(WindowEvent e) {
    }

    @Override
    public void windowOpened(WindowEvent e) {
    }
}
