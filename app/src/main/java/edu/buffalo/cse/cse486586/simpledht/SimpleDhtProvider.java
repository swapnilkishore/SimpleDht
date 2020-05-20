package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.Buffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Map;
import java.util.TreeMap;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;
public class SimpleDhtProvider extends ContentProvider {
    static final String TAG = SimpleDhtProvider.class.getSimpleName();
    private Uri newUri;
    static final int SERVER_PORT = 10000;
    static final String REMOTE_PORT0 = "11108";
    static  String myPort = "";
    private String node_id;
    private String predecessor_id;
    private String successor_id;
    private String node_hash;
    private String predecessor_hash;
    private String successor_hash;
    Map<String, String> nodes = new TreeMap<String, String>(); // We use TreeMap instead of HashMap for convenience as TreeMap is ordered by keys. Reference for treemap taken from https://howtodoinjava.com/sort/java-sort-map-by-key/
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        if(selection.contains("@")|| selection.contains("*"))
        {
            File[] files = getContext().getFilesDir().listFiles();
            for(File file : files)
            {
                file.delete();
            }
        }
        else
        {
            File file = new File(getContext().getFilesDir(), selection);
            if(file.exists())
                file.delete();
        }
        return 0;
    }


    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        String key = (String)values.get("key");
        String hash_key = "";
        try
        {
            hash_key = genHash(key);
        } catch (NoSuchAlgorithmException e)
        {
            Log.e(TAG, "Error in hashing insert key");
        }
        if(toDeliver(hash_key))
        {
            try
            {
                FileOutputStream fileOutput = getContext().getApplicationContext().openFileOutput(key, Context.MODE_PRIVATE);
                fileOutput.write(values.get("value").toString().getBytes());
                fileOutput.close();
                Log.v(TAG, values.toString());
            } catch (Exception e)
            {
                Log.e(TAG, "Error in writing file");
            }
        }
        else
        {
            String insert_message = myPort + "-" + successor_id + "-" + "" + "-" + "INSERT" + "-" + key + "-" + values.get("value") + "-" + "";
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, insert_message);
            Log.e(TAG, "INSERTING TO OTHER NODE");
        }
        return null;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        newUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        node_id = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(node_id) * 2));
        Log.e(TAG, String.valueOf(node_id));
        String temp = "";
        try
        {
            temp = genHash("5554");
        } catch (NoSuchAlgorithmException e)
        {
            Log.e(TAG, "Error in hashing node");
        }
        nodes.put(temp, "5554");
        try {
            node_hash = genHash(node_id);
        } catch (NoSuchAlgorithmException e)
        {
            Log.e(TAG, "Exception in hashing node id");
        }
        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "IOException in server socket");
        }
        predecessor_id = node_id;
        successor_id = node_id;
        Log.e(TAG, Integer.toString(Integer.parseInt(myPort)));
        if(!myPort.equals(REMOTE_PORT0))
        {
            String message = myPort + "-" + "JOIN";
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, message);
            Log.e(TAG, "ClientTask called");
        }
        return false;
    }
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        // TODO Auto-generated method stub
        String[] cols = new String[]{"key", "value"};
        MatrixCursor cursor = new MatrixCursor(cols);
        String queryNode = myPort;
        Log.e(TAG, successor_id);
        Log.e(TAG, predecessor_id);
        if (successor_id.equals(node_id) && predecessor_id.equals(node_id)) {
            if (selection.equals("*") || selection.equals("@")) {
                Log.e(TAG, "ALL QUERY");
                File[] files = getContext().getFilesDir().listFiles();
                for (File file : files) {
                    try {
                        String key = file.getName();
                        FileInputStream fileInputStream = new FileInputStream(file);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                        String line = reader.readLine();
                        reader.close();
                        fileInputStream.close();
                        String newRow[] = new String[]{key, line};
                        cursor.addRow(newRow);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return cursor;
            } else {
                Log.e(TAG, "SINGLE QUERY");
                try {
                    File fileInput = new File(getContext().getFilesDir().getAbsolutePath() + File.separator + selection);
                    FileInputStream fileInputStream = new FileInputStream(fileInput);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                    String line = reader.readLine();
                    reader.close();
                    String newRow[] = new String[]{selection, line};
                    cursor.addRow(newRow);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return cursor;
            }
        } else {
            Log.e(TAG, "MULTIPLE NODES");
            if (selection.equals("@")) {
                Log.e(TAG, "DUMPALLFROMMYSELF QUERY");
                File[] files = getContext().getFilesDir().listFiles();
                for (File file : files) {
                    try {
                        String key = file.getName();
                        FileInputStream fileInputStream = new FileInputStream(file);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                        String line = reader.readLine();
                        reader.close();
                        fileInputStream.close();
                        String newRow[] = new String[]{key, line};
                        cursor.addRow(newRow);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return cursor;
            } else if (selection.equals("*")) {
                Log.e(TAG, "DUMPALL QUERY");
                File[] files = getContext().getFilesDir().listFiles();
                for (File file : files) {
                    try {
                        String key = file.getName();
                        FileInputStream fileInputStream = new FileInputStream(file);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                        String line = reader.readLine();
                        reader.close();
                        fileInputStream.close();
                        String newRow[] = new String[]{key, line};
                        cursor.addRow(newRow);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                String toSend = successor_id;
                try {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(toSend) * 2);
                    String message = myPort + "-" + toSend + "-" + "" + "-" + "DUMPALL" + "-" + "*" + "-" + queryNode;
                    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                    outputStream.writeUTF(message);
                    outputStream.flush();
                    Log.e(TAG, "FORWARDING ALL QUERY");
                    DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                    String response = inputStream.readUTF();
                    Log.e(TAG, "RECEIVED DUMPALL REPONSE");
                    Log.e(TAG, response);
                    if(!response.equals(":")) {
                        cursor = (MatrixCursor) stringToCursor(cursor, response);
                        socket.close();
                    }
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return cursor;
            } else {
                Log.e(TAG, "MULTIPLE NODES SINGLE QUERY");
                String queryHash = "";
                try {
                    queryHash = genHash(selection);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                if (toDeliver(queryHash)) {
                    Log.e(TAG, "I HAVE IT");
                    try {
                        File fileInput = new File(getContext().getFilesDir().getAbsolutePath() + File.separator + selection);
                        FileInputStream fileInputStream = new FileInputStream(fileInput);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                        String line = reader.readLine();
                        reader.close();
                        String newRow[] = new String[]{selection, line};
                        cursor.addRow(newRow);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    return cursor;
                } else {
                    Log.e(TAG, "SENDING TO SUCCESSOR");
                    try {
                        String toSend = successor_id;
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(toSend) * 2);
                        String message = myPort + "-" + "" + "-" + "" + "-" + "DUMPONE" + "-" + selection + "-" + queryNode;
                        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                        outputStream.writeUTF(message);
                        outputStream.flush();
                        Log.e(TAG, "SENT TO SUCCESSOR");
                        DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                        String response = inputStream.readUTF();
                        socket.close();
                        String[] response_message = response.split(":");
                        String newRow[] = new String[]{response_message[0], response_message[1]};
                        cursor.addRow(newRow);
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    return cursor;
                }
            }
        }
    }

    private Cursor stringToCursor(MatrixCursor cursor, String response) {
        String[] keys_values = response.split(":");
                        String[] keys = keys_values[0].split("-");
                        if (keys.length > 0) {
                            String[] values = keys_values[1].split("-");
                            for (int i = 0; i < keys.length; i++) {
                                String newRow[] = new String[]{keys[i], values[i]};
                                cursor.addRow(newRow);
                            }
                        }
                        return cursor;
    }


    private String queryHandler(String selection, String queryNode) {
        //ADD CODE HERE
        Log.e(TAG, "IN QUERY HANDLER");
        String response = "";
        String key = "";
        String value = "";
        if (selection.equals("*")) {
            Log.e(TAG, "DUMPALL QH");
            Log.e(TAG, successor_id);
            Log.e(TAG, queryNode);
            String succesor_node = String.valueOf(Integer.parseInt(successor_id) * 2);
            if (!succesor_node.equals(queryNode)) {
                try {
                    Log.e(TAG, "forwarding to successor");
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(successor_id) * 2);
                    String message = myPort + "-" + "" + "-" + "" + "-" + "DUMPALL" + "-" + "*" + "-" + queryNode;
                    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                    outputStream.writeUTF(message);
                    outputStream.flush();
                    DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                    response = inputStream.readUTF();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if (response != "") {
                String[] keys_values = response.split(":");
                if (keys_values.length == 2) {
                    String[] keys = keys_values[0].split("-");
                    String[] values = keys_values[1].split("-");
                    for (int i = 0; i < keys.length; i++) {
                        key = key + "-" + keys[i];
                        value = value + "-" + values[i];
                    }
                }
            }

            File[] files = getContext().getFilesDir().listFiles();
            for (File file : files) {
                try {
                    Log.e(TAG, "Looping through files");
                    String name = file.getName();
                    Log.e(TAG, name);
                    FileInputStream fileInputStream = new FileInputStream(file);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                    String line = reader.readLine();
                    reader.close();
                    fileInputStream.close();

                    key = key + "-" + name;
                    Log.e(TAG, key);
                    value = value + "-" + line;
                    Log.e(TAG, value);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if (key.length() > 0) {
                key = key.substring(1);
                value = value.substring(1);
            }

            Log.e(TAG, key);
            Log.e(TAG, value);
            String reply = key + ":" + value;
            Log.e(TAG, reply);
            Log.e(TAG, "RETURNED ALL FILES FROM QH");
            return reply;
        } else {
            String queryHash = "";
            try {
                queryHash = genHash(selection);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            if (toDeliver(queryHash)) {
                String my_key = "";
                try {
                    File fileInput = new File(getContext().getFilesDir().getAbsolutePath() + File.separator + selection);
                    FileInputStream fileInputStream = new FileInputStream(fileInput);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(fileInputStream));
                    String line = reader.readLine();
                    reader.close();
                    fileInputStream.close();
                    my_key = selection + ":" + line;
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return my_key;
            } else {
                if (!successor_id.equals(node_id)) {
                    String toSend = successor_id;
                    try {
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(toSend) * 2);
                        String message = myPort + "-" + "" + "-" + "" + "-" + "DUMPONE" + "-" + selection + "-" + queryNode;
                        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                        outputStream.writeUTF(message);
                        DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                        response = inputStream.readUTF();
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    Log.e(TAG, "RETURNED RESPONSE TO SERVERTASK");
                    return response;
                } else {
                    return null;
                }
            }
        }
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }
    private class ClientTask extends AsyncTask<String, Void, String>
    {
        @Override
        protected String doInBackground(String... msgs) {
            String message = msgs[0];
            String[] splits = message.split("-");
            if (splits[1].equals("JOIN")) {
                Log.e(TAG, "Sending join request");
                try {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(REMOTE_PORT0));
                    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                    outputStream.writeUTF(message);
                    outputStream.flush();
                    Log.e(TAG, "SENT JOIN REQUEST");
                } catch (UnknownHostException e) {
                    Log.e(TAG, "UNKOWNHOST");
                } catch (IOException e) {
                    Log.e(TAG, "IOEXCEPTION");
                }
            } else if (splits[3].equals("UPDATED")) {
                try {
                    Log.e(TAG, splits[0]);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(splits[0]));
                    DataOutputStream outputStream1 = new DataOutputStream(socket.getOutputStream());
                    String update_reply = splits[0] + "-" + splits[1] + "-" + splits[2] + "-" + "REPLIED";
                    outputStream1.writeUTF(update_reply);
                    outputStream1.flush();
                    Log.e(TAG, "SENT UPDATE TO REQUESTOR");
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else if(splits[3].equals("INSERT"))
            {
                try
                {
                    Log.e(TAG, "INSERT MESSAGE GOING TO SUCCESSOR");
                    String sending = splits[1];
                    String sending_port = String.valueOf(Integer.parseInt(sending) * 2);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(sending_port));
                    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                    outputStream.writeUTF(message);
                    outputStream.flush();
                    Log.e(TAG, "SENT INSERT MESSAGE TO SUCCESSOR");
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return null;
        }

    }
    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {
        @Override
        protected Void doInBackground(ServerSocket... serverSockets) {
            while (true) {
                Log.e(TAG, "SERVER STARTED");
                try {
                    ServerSocket serverSocket = serverSockets[0];
                    Socket server = serverSocket.accept();
                    DataInputStream inputStream = new DataInputStream(server.getInputStream());
                    DataOutputStream outputStream = new DataOutputStream(server.getOutputStream());
                    String message = inputStream.readUTF();
                    Log.e(TAG, "READ MESSAGE");
                    Log.e(TAG, message);
                    String[] message_splits = message.split("-");
                    if (message_splits[1].equals("JOIN")) {
                        Log.e(TAG, "JOIN REQUEST RECEIVED");
                        int portnum = Integer.parseInt(message_splits[0]) / 2;
                        Log.e(TAG, String.valueOf(portnum));
                        Log.e(TAG, genHash(String.valueOf(portnum)));
                        nodes.put(genHash(String.valueOf(portnum)), String.valueOf(portnum));
                        String[] values = nodes.values().toArray(new String[nodes.size()]);

                        String[] keys = nodes.keySet().toArray(new String[nodes.size()]);
                        for(String key : keys)
                        {
                            Log.e(TAG, key);
                        }

                        for (int i = 0; i < values.length; i++) {
                            Log.d("i is:", Integer.toString(i));
                            Log.d("node i is:", values[i]);
                            String updatemessage = updatePS(values, i);
                            String strReceived = updatemessage.trim();
                            String to_send[] = strReceived.split("-");
                            if (to_send[3].equals("UPDATED")) {
                                 Log.e(TAG, "Calling CLientTask from server in background");
                                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, strReceived);
                             }
                        }
                    }
                    else if(message_splits[3].equals("REPLIED"))
                    {
                        Log.e(TAG, "Received reply");
                        successor_id = message_splits[1];
                        predecessor_id = message_splits[2];
                        successor_hash = genHash(successor_id);
                        predecessor_hash = genHash(predecessor_id);
                        Log.e(TAG, "UPDATED PRED/SUCCESSOR");
                        Log.d(TAG, successor_id);
                        Log.d(TAG, predecessor_id);
                        server.close();
                    }
                    else if(message_splits[3].equals("INSERT"))
                    {
                        Log.e(TAG, "RECEIVED INSERT MESSAGE");
                        String key = message_splits[4];
                        String value = message_splits[5];
                        ContentValues cv = new ContentValues();
                        cv.put("key", key);
                        cv.put("value", value);
                        insert(newUri, cv);
                        Log.e(TAG, "CALLED INSERT FUNCTION");
                    }
                    else if(message_splits[3].equals("DUMPALL"))
                    {
                        String response = queryHandler(message_splits[4], message_splits[5]);
                        outputStream.writeUTF(response);
                        outputStream.flush();
                        Log.e(TAG, "SENT DUMPALL RESPONSE");
                        Log.e(TAG, response);
                        server.close();
                    }
                    else if(message_splits[3].equals("DUMPONE"))
                    {
                        Log.e(TAG, "DUMPONE REQUEST");
                        String response = queryHandler(message_splits[4], message_splits[5]);
                        outputStream.writeUTF(response);
                        outputStream.flush();
                        Log.e(TAG, "SENT VALUE BACK TO REQUESTOR");
                        server.close();
                    }
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private String updatePS(String[] values, int i) {
        String successor = "";
        String predecessor = "";
        if (i == (values.length - 1)) {
            predecessor = values[i - 1];
            successor = values[0];
        } else if (i == 0) {
            predecessor = values[values.length - 1];
            successor = values[i + 1];
        } else {
            successor = values[i + 1];
            predecessor = values[i - 1];
        }
        int portint = Integer.parseInt(values[i]) * 2;
        String port = Integer.toString(portint);
        String reply = port + "-" + successor + "-" + predecessor + "-" + "UPDATED";
        return reply;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

    private boolean toDeliver(String hashed_value)
    {
        if(node_id.equals(predecessor_id) && node_id.equals(successor_id))
        {
            return true;
        }
        else if((hashed_value.compareTo(predecessor_hash) > 0) && (hashed_value.compareTo(node_hash) < 0))
        {
            return true;
        }
        else if((predecessor_hash.compareTo(node_hash) > 0) && (node_hash.compareTo(hashed_value) > 0))
        {
            return true;
        }
        else if((predecessor_hash.compareTo(node_hash) > 0) && (hashed_value.compareTo(predecessor_hash) > 0))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}
