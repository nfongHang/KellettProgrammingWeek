<html style="background-color:#1b1b1b;">
    <head>
        <title>Kellett Programming | Sign Up</title>
        <link rel="stylesheet" href="styles.css">
        <link rel="icon" type="image/png" href="kellett_logo.png"/>
    </head>

    <body>
        <div id="top_bar">
            Kellett Programming Week
        </div>

        <div style = "width: 75%; height: 37%" id="box">

            <div id="line_num">
                01 | <span id="class_text">import sign_up</span>
            </div>

            <div id="line_num">
                02 | <span id="commenttext"># please enter username, email and password</span>
            </div>

            <!-- input username -->
            <div id="line_num">
                03 | 
                <span id="vartext">username</span> 
                <span id="normaltext">=</span>
                <span id="inputtext">input(</span><!--
             --><span id="stringtext">"</span><!--
             --><input type="text_input" style="width: 9.5ch" onkeypress="if (parseInt(this.style.width)<=45){this.style.width = (this.value.length + 2)+'ch'}; 
                                                                          if(parseInt(this.value.length)<=45){this.style.width=(this.value.length+2)+'ch'};"
                                                                          id = "text_input"  placeholder=your_name><!--
             --><span id="stringtext">"</span><!--
             --><span id="inputtext">)</span> 
            </div>
            
            <!-- email login box -->
            <div id="line_num">
                04 | 
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
                05 | 
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
                06 | 
                <span id="vartext">retype_password</span> 
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
            06 | <input type="submit" id = "button" value = "sign_up()"><br>
            </div>
            <div id="line_num">
                06 | <div id="commenttext"></div>
            </div>
            <div id="line_num">
                07 | <span id="commenttext"># login:</span> 
            </div>
            <div id="line_num">
                08 | <span id="commenttext"># already got an account? </span><!--
             --><a><form style="display : inline" action="login.php"><input type="submit" id = "link_button" value = "login here!" /></form></a>
            </div>
        </div>
    </body>
</html>