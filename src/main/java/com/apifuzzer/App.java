package com.apifuzzer;

import com.apifuzzer.ui.MainLayout;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class App extends Application {

    @Override
    public void start(Stage stage) {

        // Create our main application layout
        MainLayout mainLayout = new MainLayout();

        Scene scene = new Scene(mainLayout, 1440, 900);

        // Load our custom application styling
        var stylesheet = getClass()
                .getResource("/styles/app.css");

        if (stylesheet != null) {
            scene.getStylesheets().add(stylesheet.toExternalForm());
        }

        stage.setTitle("api-fuzzer-basic | API Security Workbench");
        stage.setMinWidth(1100);
        stage.setMinHeight(700);
        stage.setScene(scene);
        stage.centerOnScreen();
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
