<?php
error_reporting(0);



class Waf {
    // 指定对应的系统日志文件
    // private $log_file = "E:\\soft\\xampp\\apache\\logs\\access.log";
    private $log_file = "/opt/lampp/logs/access_log";


    private $rule_file = "waf.rules";
    private $line_number = 0;  // 初始化规则文件的行数
    private $rule = array();
    private $now_time;
    private $state;   //规则相应执行的动作
    private $wid;     //规则编号

    function __construct() {
        $this->now_time = time();  //现在的时间
        
        $this->read_rule_file();

    }


    // 提取数据
    private function get_request_uri() {
		if( isset($_SERVER['PHP_SELF']) ) 
            return $_SERVER['PHP_SELF'];
		return "";
	}
    private function get_http_stat_code() {
        $command = "tail $this->log_file";
        $data = shell_exec($command);
        // preg_match_all('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\S+\s\S+\s\S+\s\S+\s".*?"\s(\d+)\s\d+\s".*?"/', $data, $pat_array);
        preg_match_all('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?"\s(\d{3})\s/', $data, $pat_array);
        // var_dump($pat_array[1]);
        $stat_code = end($pat_array[1]);
        if (preg_match("/\d{3}/", $stat_code))
            return $stat_code;
		return "";
	}
    private function get_http_method() {
		if( isset($_SERVER['REQUEST_METHOD']) )
            return $_SERVER['REQUEST_METHOD'];
		return "";
	}
    private function get_http_header() {
        $headers = array(); 
        foreach ($_SERVER as $key => $value) {
            if ('HTTP_' == substr($key, 0, 5)) { 
                $headers[str_replace('_', '-', substr($key, 5))] = $value; 
            }
            if (isset($_SERVER['PHP_AUTH_DIGEST'])) { 
                $header['AUTHORIZATION'] = $_SERVER['PHP_AUTH_DIGEST']; 
            } elseif (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) { 
                $header['AUTHORIZATION'] = base64_encode($_SERVER['PHP_AUTH_USER'] . ':' . $_SERVER['PHP_AUTH_PW']); 
            } 
            if (isset($_SERVER['CONTENT_LENGTH'])) { 
                $header['CONTENT-LENGTH'] = $_SERVER['CONTENT_LENGTH']; 
            } 
            if (isset($_SERVER['CONTENT_TYPE'])) { 
                $header['CONTENT-TYPE'] = $_SERVER['CONTENT_TYPE']; 
            }
        }
        return $headers;
    }
    private function get_http_cookie() {
        return $_COOKIE;
	}
    private function get_http_client_body() {
        $request_post = file_get_contents('php://input');
        return $request_post;
	}
    private function get_dest_ip() {
        if (isset($_SERVER["SERVER_ADDR"])) {
            return $_SERVER['SERVER_ADDR'];
        }
        return "";
    }
    private function get_src_ip() {
        if (isset($_SERVER["HTTP_CLIENT_IP"])){
            $ip = $_SERVER["HTTP_CLIENT_IP"];
        }else if (isset($_SERVER["HTTP_X_FORWARDED_FOR"])){
            $ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
        }else if (isset($_SERVER["REMOTE_ADDR"])){
            $ip = $_SERVER["REMOTE_ADDR"];
        }else if (isset($_SERVER['REMOTE_ADDR'])){
            $ip = $_SERVER['REMOTE_ADDR'];
        }else{
            $ip = "";
        }
        return $ip;    
    }
    private function get_user_agent() {
		if( isset($_SERVER['HTTP_USER_AGENT']) )
            return $_SERVER['HTTP_USER_AGENT'];
		return "";
	}
    private function get_referer() {
		if( isset($_SERVER['HTTP_REFERER']) )
            return $_SERVER['HTTP_REFERER'];
		return "";
	}


    // 功能性函数：规则编写错误输出
    private function rule_error_output($explain="自行查找") {
        return "第".$this->line_number."行规则编写错误; 错误原因: $explain";
    }
    // 功能性函数：检查是否为大于1的正整数
    private function is_positive_integer($number) {
        return (preg_match("/^[1-9]|[1-9]\d+$/", $number));  
    }
    // 功能性函数：用于退出
    private function finish() {
        #echo "请求不匹配。";
    }
    // 功能性函数：写入日志
    private function write_log() {
        file_put_contents("waf.log", $this->rule[$this->wid]["rule"], FILE_APPEND | LOCK_EX);
    }
    // 功能性函数：警告操作
    private function alert() {
        $this->write_log();
    }
    // 功能性函数：封禁操作
    private function drop() {
        $this->write_log();
        $ip = $this->get_src_ip();
        echo $ip;
	// 使用frewalld防火墙封禁ip一小时
        $output = shell_exec("sudo firewall-cmd --add-rich-rule='rule family=ipv4 source address=".$ip." drop' --timeout=3600");
        if (preg_match("/success/", $output)) {
            echo "$ip 已封禁";
        } else {
            die("防火墙封禁失败,错误消息:$output");
        }
    }


    // 函数执行步骤

    // 1、读取规则文件
    private function read_rule_file() {
        $file=fopen("$this->rule_file","r") or exit("$this->rule_file file does not exist");
        // 读取文件每一行，直到文件结尾
        while(!feof($file)) {
            $line = fgets($file);
            ++$this->line_number;
            if (preg_match("/^wid/", $line)) {
                $this->text_parsing($line);
            }
        }

        foreach ($this->rule as $key => $value) {
            $this->wid = $key;
            // 判断对应的规则状态
            if (isset($this->rule[$key]["alert"])) {
                $this->state = "alert";
            } elseif (isset($this->rule[$key]["drop"])) {
                $this->state = "drop";
            }
            // echo $this->wid . "=" . $this->state . "</br>";
            // 检查规则
            $this->check_rule($this->rule[$key][$this->state]);
            // echo "第".$a++."次</br>";
        }

        fclose($file);
    }

    // 2、解析规则,并保存至数组中
    private function text_parsing($line) {
        // 先判断规则格式是否正确
        if (preg_match('/^wid:\d+;msg:.*?;(alert|drop)\s[(].*?[)]\s*$/', $line)) {
            preg_match_all('/^wid:(\d+);msg:(.*?);(alert|drop)\s[(](.*?)[)]\s*$/', $line, $pat_array);
            $arr1 = preg_split("/;/", $pat_array[4][0]);
            $arr2 = array();
            foreach ($arr1 as $value) {
                $arr3 = preg_split("/:/", $value);
                $arr2[$arr3[0]] = $arr3[1];
            }

            $arr4 = [
                "wid" => $pat_array[1][0],
                "msg" => $pat_array[2][0],
                "rule" => $line,
                $pat_array[3][0] => $arr2
            ];
            $this->rule[$pat_array[1][0]] = $arr4;
            // var_dump($arr4);
        }
        else {
            die($this->rule_error_output());
        }
    }

    // 3、检查具体规则是否正确
    private function check_rule($array) {
        $rule_keyword = [  // 规则关键字
            "request_uri",
            "http_stat_code",
            "http_method",
            "http_header",
            "http_cookie",
            "http_client_body",
            "user_agent",
            "referer"
        ];
        $main = 0;
        $target = 0;
        $count = 0;
        $time = 0;

        // 判断关键字是否正确
        foreach ($array as $key => $value) {
            if (in_array($key, $rule_keyword)) {
                ++$main;
                if ($this->check_field_value($key, $value) !== 1) {
                    // 正则不匹配跳转至结束函数
                    $this->finish();
                }

            } elseif ($key === "target") {  
                // 判断关键字对应的值是否正确
                if ($value === "src_ip" || $value === "dest_ip") {
                    $target = $value;
                } else {
                    die($this->rule_error_output("错误的值 target=>$value"));
                }

            } elseif ($key === "count") {
                if ($this->is_positive_integer($value)) {
                    $count = $value;
                } else {
                    die($this->rule_error_output("count为大于0的正整数,现在count的值为=>$value"));
                } 

            } elseif ($key === "time") {
                if ($this->is_positive_integer($value)) {
                    $time = $value;
                } else {
                    die($this->rule_error_output("time为大于0的正整数,现在time的值为=>$value"));
                } 

            } else {
                die($this->rule_error_output("存在错误的规则关键字=>$key"));
            }
        }

        // 判断过滤内容
        if (!$main) {
            die($this->rule_error_output("每一条规则必须存在一个过滤内容"));
        } elseif ($target && $count === 0 && $time === 0) {
            die($this->rule_error_output("请满足target的前置条件"));
        } elseif ($count || $time) {
            // echo "调试 count=$count";
            $flag = "";  //定义标志位
            $wirte_data = "wid:".$this->wid.";";
            if ($count) {
                //次数要求为1的时候，直接执行操作
                if ($count == 1) {
                    $state = $this->state;
                    $state();
                }
                $wirte_data .= "count:$count;now_count:1;";
                $flag .= "c";
            }
            if ($time) {
                $end_time = $this->now_time + $time;
                $wirte_data .= "end_time:$end_time;";
                $flag .= "t";
            } 

            if ($target) {
                $name = "get_".$target;
                $ip = $this->$name();
                $wirte_data .= "$target:$ip;";
                $flag .= "i";
            }

            // 调用计数函数
            // echo "wirte_data: " . $wirte_data.",flag: ".$flag;
            $this->count_file($wirte_data, $flag);
        } else {
            $state = $this->state;
            $state();
        }
    }

    // 4、正则匹配具体的内容是否符合条件
    private function check_field_value($method, $pcre) {
        $method_name = "get_".$method;  // 拼接方法名
        $data = $this->$method_name();  // 获取数据

        // 判断是否为数组
        if (is_array($data)) {
            $data2 = "";
            // 判断是否为空数组，空数组则为字符串的""空。
            if ($data) {
                foreach ($data as $key => $value) {
                    $data2 .= $key.":".$value."\n";
                }
            }
            $data = $data2;
        }
        #echo "pcre=$pcre, data=$data</br>";
        return (preg_match("$pcre", $data));  
    }

    // 5、操作计数文件，并检查
    private function count_file($data, $flag) {
        $file_data = file_get_contents("count.txt");

        //如果计数文件等于空，那么直接写入
        if ($file_data === "") {
            file_put_contents("count.txt", "$data\n");
        } 
        else {  
            // 定义正则表达式，用于匹配计数文件中的规则
            $wid = $this->wid;
            $reg = "wid:$wid;";
            $c=0;$t=0;$i=0;
            if (strstr($flag, "c")) {
                $count = $this->rule[$wid][$this->state]["count"];
                $reg .= "count:$count;now_count:(\d+);";
                ++$c;
            } 
            if (strstr($flag, "t")) {
                $reg .= "end_time:(\d+);";
                ++$t;
            } 
            if (strstr($flag, "i")) {
                $target = $this->rule[$wid][$this->state]["target"];
                $name = "get_".$target;
                $ip = $this->$name();
                $reg .= "$target:($ip);";
                ++$i;
            }
            // echo $file_data."</br>" .$reg;
            // echo preg_match_all("/$reg/", $file_data, $pat_array);

            // 判断是否已写入
            if (preg_match_all("/$reg/", $file_data, $pat_array)) {

                // 判断规则是否有时间条件
                if ($t) {
                    $end_time = $pat_array[2][0];
                    // 如果现在的时间大于规则的最后时间，把规则删除，重写
                    if ($this->now_time > $end_time) {
                        $file_data = preg_replace("/\s*$reg\s*/", "", $file_data); 
                        $file_data .= "$data\n";
                        file_put_contents("count.txt", trim($file_data));
                    } 
                    // 在有时间条件的基础上判断是否是否有数量条件
                    if ($c) {
                        // 有目标的限定，且两次目标的值一样
                        if ($i && $ip === $pat_array[3][0]) {
                            $now_count = $pat_array[1][0] + 1;  //次数加一
                            // echo $now_count;
                            // 判断次数是否达标
                            if ($count == $now_count) {
                                // 删除规则
                                $reg = "/wid:$wid;count:$count;now_count:(\d+);end_time:\d+;$target:$ip;/";
                                $file_data = preg_replace($reg, "", $file_data);
                                file_put_contents("count.txt", trim($file_data));

                                // 次数达标执行操作
                                $stat = $this->state;
                                $this->$stat();
                            } else {
                                // 更改文件，让次数加1
                                $reg = "/wid:$wid;count:$count;now_count:(\d+);end_time:\d+;$target:$ip;/";
                                $replace = "wid:$wid;count:$count;now_count:$now_count;end_time:$end_time;$target:$ip;";
                                // echo $file_data."</br>".$reg."</br>".$replace."<br>";

                                $file_data = preg_replace($reg, $replace, $file_data);
                                // echo "</br>".$file_data."</br>".$reg."</br>".$replace."<br>";

                                file_put_contents("count.txt", trim($file_data));
                            }
                        }
                        // 没有目标的限定
                        if (!$i) {
                            $now_count = $pat_array[1][0] + 1;  //次数加一
                            // 判断次数是否达标
                            if ($count == $now_count) {
                                // 删除规则
                                $reg = "/wid:$wid;count:$count;now_count:(\d+);end_time:\d+;/";
                                $file_data = preg_replace($reg, "", $file_data);
                                file_put_contents("count.txt", trim($file_data));

                                // 次数达标执行操作
                                $stat = $this->state;
                                $this->$stat();
                            } else {
                                // 更改文件，让次数加1
                                $reg = "/wid:$wid;count:$count;now_count:(\d+);end_time:\d+;/";
                                $replace = "wid:$wid;count:$count;now_count:$now_count;end_time:$end_time;";

                                $file_data = preg_replace($reg, $replace, $file_data);

                                file_put_contents("count.txt", trim($file_data));
                            }
                        }
                    }

                } 
                if ($c) {
                    if ($i && $ip === $pat_array[2][0]) {
                        $now_count = $pat_array[1][0] + 1;  //次数加一
                        // 判断次数是否达标
                        if ($count == $now_count) {
                            // 删除规则
                            $reg = "/wid:$wid;count:$count;now_count:(\d+);$target:$ip;/";
                            $file_data = preg_replace($reg, "", $file_data);
                            file_put_contents("count.txt", trim($file_data));

                            // 次数达标执行操作
                            $stat = $this->state;
                            $this->$stat();
                        } else {
                            // 更改文件，让次数加1
                            $replace = "wid:$wid;count:$count;now_count:$now_count;$target:$ip;";
                            $reg = "/wid:$wid;count:$count;now_count:(\d+);$target:$ip;/";
                            // echo "</br>".$file_data."</br>".$reg."</br>".$replace."<br>";
                            $file_data = preg_replace($reg, $replace, $file_data);
                            // echo "</br>".$file_data."</br>".$reg."</br>".$replace."<br>";
                            file_put_contents("count.txt", trim($file_data));
                        }
                    }
                    if (!$i) {
                        $now_count = $pat_array[1][0] + 1;  //次数加一
                        // 判断次数是否达标
                        if ($count == $now_count) {
                            // 删除规则
                            $reg = "/wid:$wid;count:$count;now_count:(\d+);/";
                            $file_data = preg_replace($reg, "", $file_data);
                            file_put_contents("count.txt", trim($file_data));

                            // 次数达标执行操作
                            $stat = $this->state;
                            $this->$stat();
                        } else {
                            // 更改文件，让次数加1
                            $replace = "wid:$wid;count:$count;now_count:$now_count;";
                            $reg = "/wid:$wid;count:$count;now_count:(\d+);/";
                            $file_data = preg_replace($reg, $replace, $file_data);

                            file_put_contents("count.txt", trim($file_data));
                        }
                    }
                }

            } else {
                // 计数文件中没有写入，添加该规则
                file_put_contents("count.txt", "$data\n", FILE_APPEND | LOCK_EX);
            }
        }
    }

}


$waf = new Waf;
