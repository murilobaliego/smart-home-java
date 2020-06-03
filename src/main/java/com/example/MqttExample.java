package com.example;

// [START iot_mqtt_includes]

import io.jsonwebtoken.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;
import org.eclipse.paho.client.mqttv3.*;
import org.eclipse.paho.client.mqttv3.persist.*;
import org.joda.time.*;

// [END iot_mqtt_includes]

/**
 * Java sample of connecting to Google Cloud IoT Core vice via MQTT, using JWT.
 *
 * This example connects to Google Cloud IoT Core via MQTT, using a JWT for device
 * authentication. After connecting, by default the device publishes 100 messages to the device's
 * MQTT topic at a rate of one per second, and then exits. To set state instead of publishing
 * telemetry events, set the `-message_type` flag to `state.`
 *
 * To run this example, first create your credentials and register your device as described in
 * the README located in the sample's parent folder.
 *
 * After you have registered your device and generated your credentials, compile and run with the
 * corresponding algorithm flag, for example:
 *
 * <pre>
 *   $ mvn compile
 *   $ mvn exec:exec -Dmqtt \
 *                   -Dproject_id=blue-jet-123 \
 *                   -Dregistry_id=my-registry \
 *                   -Ddevice_id=my-test-device \
 *                   -Dalgorithm=RS256 \
 *                   -Dprivate_key_file="../path/to/your_private_pkcs8"
 * </pre>
 */
public class MqttExample {
    // [START iot_mqtt_jwt]
    // [START iot_mqtt_configcallback]
    static MqttCallback mCallback;
    static long MINUTES_PER_HOUR = 60;

    private static String cloudRegion = "us-central1";
    private static int numMessages = 100;
    private static int tokenExpMins = 20;
    private static String telemetryData = "projects/smart-devices-mbfa/topics/murilo/dev1";

    private static String mqttBridgeHostname = "mqtt.googleapis.com";
    private static short mqttBridgePort = 8883;
    private static String messageType = "event";
    private static int waitTime = 120;
    private static String projectId = "smart-devices-mbfa"; //commandLine.getOptionValue("project_id");
    private static String registryId = "atest-registry"; //commandLine.getOptionValue("registry_id");
    private static String deviceId = "atest-dev"; //commandLine.getOptionValue("device_id");
    private static String privateKeyFile = "ec_private_pkcs8"; //commandLine.getOptionValue("private_key_file");
    private static String algorithm = "ES256"; //commandLine.getOptionValue("algorithm");
    private static String gatewayId = "java_backend";


    /** Create a Cloud IoT Core JWT for the given project id, signed with the given RSA key. */
    private static String createJwtRsa(String projectId, String privateKeyFile)
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        DateTime now = new DateTime();
        // Create a JWT to authenticate this device. The device will be disconnected after the token
        // expires, and will have to reconnect with a new token. The audience field should always be set
        // to the GCP project id.
        JwtBuilder jwtBuilder =
                Jwts.builder()
                        .setIssuedAt(now.toDate())
                        .setExpiration(now.plusMinutes(20).toDate())
                        .setAudience(projectId);

        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return jwtBuilder.signWith(SignatureAlgorithm.RS256, kf.generatePrivate(spec)).compact();
    }
    // [END iot_mqtt_jwt]

    /** Create a Cloud IoT Core JWT for the given project id, signed with the given ES key. */
    private static String createJwtEs(String projectId, String privateKeyFile)
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        DateTime now = new DateTime();
        // Create a JWT to authenticate this device. The device will be disconnected after the token
        // expires, and will have to reconnect with a new token. The audience field should always be set
        // to the GCP project id.
        JwtBuilder jwtBuilder =
                Jwts.builder()
                        .setIssuedAt(now.toDate())
                        .setExpiration(now.plusMinutes(20).toDate())
                        .setAudience(projectId);

        Path pathToFile = Paths.get(privateKeyFile);
        System.out.println(pathToFile.toAbsolutePath());

        byte[] keyBytes = Files.readAllBytes(Paths.get(pathToFile.toAbsolutePath().toString()));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");

        return jwtBuilder.signWith(SignatureAlgorithm.ES256, kf.generatePrivate(spec)).compact();
    }

    /** Connects the gateway to the MQTT bridge. */
    protected static MqttClient startMqtt(
            String mqttBridgeHostname,
            int mqttBridgePort,
            String projectId,
            String cloudRegion,
            String registryId,
            String gatewayId,
            String privateKeyFile,
            String algorithm)
            throws NoSuchAlgorithmException, IOException, MqttException, InterruptedException,
            InvalidKeySpecException {
        // [START iot_gateway_start_mqtt]

        // Build the connection string for Google's Cloud IoT Core MQTT server. Only SSL
        // connections are accepted. For server authentication, the JVM's root certificates
        // are used.
        final String mqttServerAddress =
                String.format("ssl://%s:%s", mqttBridgeHostname, mqttBridgePort);

        // Create our MQTT client. The mqttClientId is a unique string that identifies this device. For
        // Google Cloud IoT Core, it must be in the format below.
        final String mqttClientId =
                String.format(
                        "projects/%s/locations/%s/registries/%s/devices/%s",
                        projectId, cloudRegion, registryId, gatewayId);

        MqttConnectOptions connectOptions = new MqttConnectOptions();
        // Note that the Google Cloud IoT Core only supports MQTT 3.1.1, and Paho requires that we
        // explictly set this. If you don't set MQTT version, the server will immediately close its
        // connection to your device.
        connectOptions.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1);

        Properties sslProps = new Properties();
        sslProps.setProperty("com.ibm.ssl.protocol", "TLSv1.2");
        connectOptions.setSSLProperties(sslProps);

        // With Google Cloud IoT Core, the username field is ignored, however it must be set for the
        // Paho client library to send the password field. The password field is used to transmit a JWT
        // to authorize the device.
        connectOptions.setUserName("unused");

        if ("RS256".equals(algorithm)) {
            connectOptions.setPassword(createJwtRsa(projectId, privateKeyFile).toCharArray());
        } else if ("ES256".equals(algorithm)) {
            connectOptions.setPassword(createJwtEs(projectId, privateKeyFile).toCharArray());
        } else {
            throw new IllegalArgumentException(
                    "Invalid algorithm " + algorithm + ". Should be one of 'RS256' or 'ES256'.");
        }

        System.out.println(String.format("%s", mqttClientId));

        // Create a client, and connect to the Google MQTT bridge.
        MqttClient client = new MqttClient(mqttServerAddress, mqttClientId, new MemoryPersistence());

        // Both connect and publish operations may fail. If they do, allow retries but with an
        // exponential backoff time period.
        long initialConnectIntervalMillis = 500L;
        long maxConnectIntervalMillis = 6000L;
        long maxConnectRetryTimeElapsedMillis = 900000L;
        float intervalMultiplier = 1.5f;

        long retryIntervalMs = initialConnectIntervalMillis;
        long totalRetryTimeMs = 0;

        while ((totalRetryTimeMs < maxConnectRetryTimeElapsedMillis) && !client.isConnected()) {
            try {
                client.connect(connectOptions);
            } catch (MqttException e) {
                int reason = e.getReasonCode();

                // If the connection is lost or if the server cannot be connected, allow retries, but with
                // exponential backoff.
                System.out.println("An error occurred: " + e.getMessage());
                if (reason == MqttException.REASON_CODE_CONNECTION_LOST
                        || reason == MqttException.REASON_CODE_SERVER_CONNECT_ERROR) {
                    System.out.println("Retrying in " + retryIntervalMs / 1000.0 + " seconds.");
                    Thread.sleep(retryIntervalMs);
                    totalRetryTimeMs += retryIntervalMs;
                    retryIntervalMs = (long) (retryIntervalMs*intervalMultiplier);
                    if (retryIntervalMs > maxConnectIntervalMillis) {
                        retryIntervalMs = maxConnectIntervalMillis;
                    }
                } else {
                    throw e;
                }
            }
        }

        attachCallback(client, gatewayId);

        // The topic gateways receive error updates on. QoS must be 0.
        String errorTopic = String.format("/devices/%s/errors", gatewayId);
        System.out.println(String.format("Listening on %s", errorTopic));

        client.subscribe(errorTopic, 0);

        return client;
        // [END iot_gateway_start_mqtt]
    }

    protected static void sendDataFromDevice(
            MqttClient client, String deviceId, String messageType, String data)
            throws MqttException, UnsupportedEncodingException {
        // [START send_data_from_bound_device]
        if (!"events".equals(messageType) && !"state".equals(messageType)) {
            System.err.println("Invalid message type, must ether be 'state' or events'");
            return;
        }
        final String dataTopic = String.format("/devices/%s/%s", deviceId, messageType);
        MqttMessage message = new MqttMessage(data.getBytes(StandardCharsets.UTF_8.name()));
        message.setQos(1);
        client.publish(dataTopic, message);
        System.out.println("Data sent");
        // [END send_data_from_bound_device]
    }

    /** Sends data on behalf of a bound device using the Gateway. */
    protected static void sendDataFromBoundDevice(
            String mqttBridgeHostname,
            short mqttBridgePort,
            String projectId,
            String cloudRegion,
            String registryName,
            String gatewayId,
            String privateKeyFile,
            String algorithm,
            String deviceId,
            String messageType,
            String telemetryData)
            throws MqttException, IOException, InvalidKeySpecException, InterruptedException,
            NoSuchAlgorithmException {
        // [START send_data_from_bound_device]
        MqttClient client =
                startMqtt(
                        mqttBridgeHostname,
                        mqttBridgePort,
                        projectId,
                        cloudRegion,
                        registryName,
                        gatewayId,
                        privateKeyFile,
                        algorithm);
        attachDeviceToGateway(client, deviceId);
        sendDataFromDevice(client, deviceId, messageType, telemetryData);
        detachDeviceFromGateway(client, deviceId);
        // [END send_data_from_bound_device]
    }

    protected static void listenForConfigMessages(
            String mqttBridgeHostname,
            short mqttBridgePort,
            String projectId,
            String cloudRegion,
            String registryName,
            String gatewayId,
            String privateKeyFile,
            String algorithm,
            String deviceId)
            throws MqttException, IOException, InvalidKeySpecException, InterruptedException,
            NoSuchAlgorithmException {
        // Connect the Gateway
        MqttClient client =
                startMqtt(
                        mqttBridgeHostname,
                        mqttBridgePort,
                        projectId,
                        cloudRegion,
                        registryName,
                        gatewayId,
                        privateKeyFile,
                        algorithm);
        // Connect the bound device and listen for configuration messages.
        attachDeviceToGateway(client, deviceId);
        attachCallback(client, deviceId);

        detachDeviceFromGateway(client, deviceId);
    }

    protected static void attachDeviceToGateway(MqttClient client, String deviceId)
            throws MqttException, UnsupportedEncodingException {
        // [START iot_attach_device]
        final String attachTopic = String.format("/devices/%s/attach", deviceId);
        System.out.println(String.format("Attaching: %s", attachTopic));
        String attachPayload = "{}";
        MqttMessage message = new MqttMessage(attachPayload.getBytes(StandardCharsets.UTF_8.name()));
        message.setQos(1);
        client.publish(attachTopic, message);
        // [END iot_attach_device]
    }

    /** Detaches a bound device from the Gateway. */
    protected static void detachDeviceFromGateway(MqttClient client, String deviceId)
            throws MqttException, UnsupportedEncodingException {
        // [START iot_detach_device]
        final String detachTopic = String.format("/devices/%s/detach", deviceId);
        System.out.println(String.format("Detaching: %s", detachTopic));
        String attachPayload = "{}";
        MqttMessage message = new MqttMessage(attachPayload.getBytes(StandardCharsets.UTF_8.name()));
        message.setQos(1);
        client.publish(detachTopic, message);
        // [END iot_detach_device]
    }

    protected static void mqttDeviceDemo()
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, MqttException,
            InterruptedException {
        // Build the connection string for Google's Cloud IoT Core MQTT server. Only SSL
        // connections are accepted. For server authentication, the JVM's root certificates
        // are used.
        final String mqttServerAddress =
                String.format("ssl://%s:%s", mqttBridgeHostname, mqttBridgePort);

        // Create our MQTT client. The mqttClientId is a unique string that identifies this device. For
        // Google Cloud IoT Core, it must be in the format below.
        final String mqttClientId =
                String.format(
                        "projects/%s/locations/%s/registries/%s/devices/%s",
                        projectId, cloudRegion, registryId, deviceId);

        MqttConnectOptions connectOptions = new MqttConnectOptions();
        // Note that the Google Cloud IoT Core only supports MQTT 3.1.1, and Paho requires that we
        // explictly set this. If you don't set MQTT version, the server will immediately close its
        // connection to your device.
        connectOptions.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1);

        Properties sslProps = new Properties();
        sslProps.setProperty("com.ibm.ssl.protocol", "TLSv1.2");
        connectOptions.setSSLProperties(sslProps);

        // With Google Cloud IoT Core, the username field is ignored, however it must be set for the
        // Paho client library to send the password field. The password field is used to transmit a JWT
        // to authorize the device.
        connectOptions.setUserName("unused");

        DateTime iat = new DateTime();
        if ("RS256".equals(algorithm)) {
            connectOptions.setPassword(
                    createJwtRsa(projectId, privateKeyFile).toCharArray());
        } else if ("ES256".equals(algorithm)) {
            connectOptions.setPassword(
                    createJwtEs(projectId, privateKeyFile).toCharArray());
        } else {
            throw new IllegalArgumentException(
                    "Invalid algorithm " + algorithm + ". Should be one of 'RS256' or 'ES256'.");
        }
        // [END iot_mqtt_configuremqtt]

        // [START iot_mqtt_publish]
        // Create a client, and connect to the Google MQTT bridge.
        MqttClient client = new MqttClient(mqttServerAddress, mqttClientId, new MemoryPersistence());

        // Both connect and publish operations may fail. If they do, allow retries but with an
        // exponential backoff time period.
        long initialConnectIntervalMillis = 500L;
        long maxConnectIntervalMillis = 6000L;
        long maxConnectRetryTimeElapsedMillis = 900000L;
        float intervalMultiplier = 1.5f;

        long retryIntervalMs = initialConnectIntervalMillis;
        long totalRetryTimeMs = 0;

        while ((totalRetryTimeMs < maxConnectRetryTimeElapsedMillis) && !client.isConnected()) {
            try {
                client.connect(connectOptions);
            } catch (MqttException e) {
                int reason = e.getReasonCode();

                // If the connection is lost or if the server cannot be connected, allow retries, but with
                // exponential backoff.
                System.out.println("An error occurred: " + e.getMessage());
                if (reason == MqttException.REASON_CODE_CONNECTION_LOST
                        || reason == MqttException.REASON_CODE_SERVER_CONNECT_ERROR) {
                    System.out.println("Retrying in " + retryIntervalMs / 1000.0 + " seconds.");
                    Thread.sleep(retryIntervalMs);
                    totalRetryTimeMs += retryIntervalMs;
                    retryIntervalMs *= intervalMultiplier;
                    if (retryIntervalMs > maxConnectIntervalMillis) {
                        retryIntervalMs = maxConnectIntervalMillis;
                    }
                } else {
                    throw e;
                }
            }
        }

        attachCallback(client, deviceId);

        // Publish to the events or state topic based on the flag.
        String subTopic = "event".equals(messageType) ? "events" : messageType;

        // The MQTT topic that this device will publish telemetry data to. The MQTT topic name is
        // required to be in the format below. Note that this is not the same as the device registry's
        // Cloud Pub/Sub topic.
        String mqttTopic = String.format("/devices/%s/%s", deviceId, subTopic);

        // Publish numMessages messages to the MQTT bridge, at a rate of 1 per second.
        for (int i = 1; i <= numMessages; ++i) {
            String payload = String.format("%s/%s-payload-%d", registryId, deviceId, i);
            System.out.format(
                    "Publishing %s message %d/%d: '%s'%n",
                    messageType, i, numMessages, payload);

            // Refresh the connection credentials before the JWT expires.
            // [START iot_mqtt_jwt_refresh]
            long secsSinceRefresh = ((new DateTime()).getMillis() - iat.getMillis()) / 1000;
            if (secsSinceRefresh > (tokenExpMins * MINUTES_PER_HOUR)) {
                System.out.format("\tRefreshing token after: %d seconds%n", secsSinceRefresh);
                iat = new DateTime();
                if ("RS256".equals(algorithm)) {
                    connectOptions.setPassword(
                            createJwtRsa(projectId, privateKeyFile).toCharArray());
                } else if ("ES256".equals(algorithm)) {
                    connectOptions.setPassword(
                            createJwtEs(projectId, privateKeyFile).toCharArray());
                } else {
                    throw new IllegalArgumentException(
                            "Invalid algorithm " + algorithm + ". Should be one of 'RS256' or 'ES256'.");
                }
                client.disconnect();
                client.connect();
                attachCallback(client, deviceId);
            }
            // [END iot_mqtt_jwt_refresh]

            // Publish "payload" to the MQTT topic. qos=1 means at least once delivery. Cloud IoT Core
            // also supports qos=0 for at most once delivery.
            MqttMessage message = new MqttMessage(payload.getBytes(StandardCharsets.UTF_8.name()));
            message.setQos(1);
            client.publish(mqttTopic, message);

            if ("event".equals(messageType)) {
                // Send telemetry events every second
                Thread.sleep(1000);
            } else {
                // Note: Update Device state less frequently than with telemetry events
                Thread.sleep(5000);
            }
        }

        // Wait for commands to arrive for about two minutes.
        for (int i = 1; i <= waitTime; ++i) {
            System.out.print('.');
            Thread.sleep(1000);
        }
        System.out.println("");

        // Disconnect the client if still connected, and finish the run.
        if (client.isConnected()) {
            client.disconnect();
        }

        System.out.println("Finished loop successfully. Goodbye!");
        client.close();
        // [END iot_mqtt_publish]
    }

    /** Attaches the callback used when configuration changes occur. */
    protected static void attachCallback(MqttClient client, String deviceId)
            throws MqttException, UnsupportedEncodingException {
        mCallback =
                new MqttCallback() {
                    @Override
                    public void connectionLost(Throwable cause) {
                        // Do nothing...
                        System.out.println("Connection Lost");
                    }

                    @Override
                    public void messageArrived(String topic, MqttMessage message) {
                        try {
                            String payload = new String(message.getPayload(), StandardCharsets.UTF_8.name());
                            System.out.println("Payload : " + payload);
                            // TODO: Insert your parsing / handling of the configuration message here.
                            //
                        } catch (UnsupportedEncodingException uee) {
                            System.err.println(uee);
                        }
                    }

                    @Override
                    public void deliveryComplete(IMqttDeliveryToken token) {
                        // Do nothing;
                    }
                };

        String commandTopic = String.format("/devices/%s/commands/#", deviceId);
        System.out.println(String.format("Listening on %s", commandTopic));

        String configTopic = String.format("/devices/%s/config", deviceId);
        System.out.println(String.format("Listening on %s", configTopic));

        client.subscribe(configTopic, 1);
        client.subscribe(commandTopic, 1);
        client.setCallback(mCallback);
    }
    // [END iot_mqtt_configcallback]

    /** Parse arguments, configure MQTT, and publish messages. */
    public static void main(String[] args) throws Exception {

        String filename="ec_private.pem";
        Path pathToFile = Paths.get(filename);
        System.out.println(pathToFile.toAbsolutePath());

        //if ("listen-for-config-messages".equals(options.command)) {
        /*    System.out.println(
                    String.format("Listening for configuration messages for %s:", deviceId));
            listenForConfigMessages(
                    mqttBridgeHostname,
                    mqttBridgePort,
                    projectId,
                    cloudRegion,
                    registryId,
                    gatewayId,
                    privateKeyFile,
                    algorithm,
                    deviceId);
                    */

        /*} else if ("send-data-from-bound-device".equals(options.command)) { */
            System.out.println("Sending data on behalf of device:");
            sendDataFromBoundDevice(
                    mqttBridgeHostname,
                    mqttBridgePort,
                    projectId,
                    cloudRegion,
                    registryId,
                    gatewayId,
                    privateKeyFile,
                    algorithm,
                    deviceId,
                    messageType,
                    telemetryData);
        /*} else {
            System.out.println("Starting mqtt demo:");
            mqttDeviceDemo(options);
        }*/
        // [END iot_mqtt_configuremqtt]
    }
}