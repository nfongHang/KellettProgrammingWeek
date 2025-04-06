<html style="background-color: #1B1B1B;">
    <head>
        <link rel="icon" type="image/png" href="kellett_logo.png"/>
        <link rel="icon" type="image/png" href="kellett_logo_light.png" media="(prefers-color-scheme:dark)"/>
        <link rel="icon" type="image/png" href="kellett_logo_dark.png" media="(prefers-color-scheme:light)"/>
        <title>Kellett Programming | Login</title>
        <link rel="stylesheet" href="styles.css">
        <script src="script.js"></script> 
    </head>
    
    <body>
        <div id="top_bar">
            Kellett Programming Week
        </div>

        <div style = "width: 75%; height: 30%" id="box">

            <div id = "line_num">
                01 | <span id="class_text">import login</span>
            </div>
            
            <div id="line_num">
                02 | <span id="commenttext"># please enter email and password to login</span>

            </div>
            <!-- email login box -->
            <div id="line_num">
                03 | 
                <span id="vartext">email</span> 
                <span id="normaltext">=</span>
                <span id="inputtext">input(</span><!--
             --><span id="stringtext">"</span><!--
             --><input type="text_input" style="width: 14.5ch" onkeypress="if (parseInt(this.style.width)<=45){this.style.width = (this.value.length + 2)+'ch'}; 
                                                                           if(parseInt(this.value.length)<=45){this.style.width=(this.value.length+2)+'ch'};"
                                                                           id = "text_input"  placeholder=name@email.com><!--
             --><span id="stringtext">"</span><!--
             --><span id="inputtext">)</span> 
            </div>
            
            <!-- input password -->
            <div id="line_num">
                04 | 
                <span id="vartext">password</span> 
                <span id="normaltext">=</span>
                <span id="inputtext">input(</span><!--
             --><span id="stringtext">"</span><!--
             --><input type="password" style="width: 8.5ch" onkeypress="if (parseInt(this.style.width)<=45){this.style.width = (this.value.length + 2)+'ch'}; 
                                                                        if(parseInt(this.value.length)<=45){this.style.width=(this.value.length+2)+'ch'};" 
                                                                        id = "text_input"  placeholder=password><!--
             --><span id="stringtext">"</span><!--
             --><span id="inputtext">)</span>
            </div>
            <div id="line_num">
                05 | <input type="submit" id = "button" value = "login()"><br>
            </div>
            <div id="line_num">
                06 | <div id="commenttext"></div>
            </div>
            <div id="line_num">
                07 | <span id="commenttext"># signup:</span> 
            </div>
            <div id="line_num">
                08 | <span id="commenttext"># havent gotten an account yet? </span><!--
             --><a><form style="display : inline" action="signup.php"><input type="submit" id = "link_button" value = "sign up here!" /></form></a>
            </div>
        </div>
    </body>
</html>