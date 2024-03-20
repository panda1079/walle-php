<?php

class V2Pack
{
    public function getvaluefrombytes($tbytes) {
        $va = 0;
        for ($j = 0; $j < count($tbytes); $j++) {
            $va += $tbytes[$j] * 256 ** $j;
        }
        return $va;
    }

    function decodebytesfromnum($num, $lens = 4) {
        $tbytes = array();
        for ($i = 0; $i < $lens; $i++) {
            $tbytes[] = ($num & (0xff << 8 * $i)) >> 8 * $i;
        }
        return $tbytes;
    }

    /**
     * 打包
     */
    public function pack($input_filepath, $out_filepath, $channel_info)
    {
        // 读取二进制文件内容
        $fileContents = file_get_contents($input_filepath);
        $byteslen = strlen($fileContents);
        $input_num = -1;

        for ($i = 0; $i < $byteslen - 22; $i++) {
            if (bin2hex($fileContents[$byteslen-22-$i]) == "50" &&bin2hex($fileContents[$byteslen-21-$i]) == "4b" &&bin2hex($fileContents[$byteslen-20-$i]) == "05" &&bin2hex($fileContents[$byteslen-19-$i]) == "06" ) {
                $input_num = $i;
            }
        }

        $start_central_directory_value_pos = -6 - $input_num;
        $start_central_directory = ord($fileContents[$start_central_directory_value_pos + 3]) * 256 ** 3 + ord($fileContents[$start_central_directory_value_pos + 2]) * 256 ** 2 + ord($fileContents[$start_central_directory_value_pos + 1]) * 256 + ord($fileContents[$start_central_directory_value_pos]);

        // 校验 APK Sig Block 42是否在 start_central_directory之前
        if (substr($fileContents, $start_central_directory - 16, 16) !== 'APK Sig Block 42') {
            return "该文件不是V2签名的apk";
        }

        $sign_block_size = 0;
        $sgin_block_value_pos = $start_central_directory - 16 - 8;

        for ($i = 0; $i < 8; $i++) {
            $sign_block_size += 256 ** $i * ord($fileContents[$sgin_block_value_pos + $i]);
        }

        # sign_block的开头位置
        $sign_block_start_pos = $start_central_directory - $sign_block_size - 8;

        $k = 0;
        $keybytes = array();
        $tempbytes = array();
        $strkey = 0;

        // 遍历区块，打印里面所有的id_value组合出来看看
        $pairlen = 0;
        for ($i = $sign_block_start_pos + 8; $i < $sgin_block_value_pos; $i++) {
            $tempbytes[] = ord($fileContents[$i]);
            if ($k == 7) {
                $pairlen = $this->getvaluefrombytes($tempbytes);
                $tempbytes = array();
            }
            if ($k == 11) {
                $strkey = $this->getvaluefrombytes($tempbytes);
                $tempbytes = array();
            }
            if ($k == $pairlen + 7) {
                $keybytes[$strkey] = implode(array_map("chr", $tempbytes));
                $tempbytes = array();
                $k = -1;
            }
            $k++;
        }

        #拼接渠道信息
        $add_data = "wwwq".json_encode($channel_info); //这里的wwwq是可以自定义的
        $datalen = strlen($add_data);
        $insertbytes = chr($datalen)."\x00\x00\x00\x00\x00\x00\x00".$add_data; //设定插入内容

        #因为要插入数据，所以对应的start_central_directory的值和sign_block_size的值要发生变化
        $start_central_directory += strlen($insertbytes);

        $dictoffsetbytes = $this->decodebytesfromnum($start_central_directory);

        // 插入魔数后校验位
        for ($index = 0; $index < 3; $index++) {
            $fileContents[$start_central_directory_value_pos + $index] = chr($dictoffsetbytes[$index]);
        }

        $sign_block_size += strlen($insertbytes);
        $signsizebytes = $this->decodebytesfromnum($sign_block_size, 8);

        // 插入区块头校验位与zip结尾校验位
        for ($index = 0; $index < 8; $index++) {
            $fileContents[$sign_block_start_pos + $index] = chr($signsizebytes[$index]);
            $fileContents[$sgin_block_value_pos + $index] = chr($signsizebytes[$index]);
        }

        // 插入渠道描述以及校验位（要注意单校验位只能容纳255-8的数据长度，渠道号尽量不要长）
        $fileContents = substr_replace($fileContents, $insertbytes, $sgin_block_value_pos , 0);

        // 写入包
        file_put_contents($out_filepath, $fileContents);
        return "OK";
    }
}


// 设置内存限制
ini_set('memory_limit', '1024M');

$input_filepath = "app-release_new-v2.apk";
$out_filepath = "ttt.apk";

$V2 = new V2Pack();
$out = $V2->pack($input_filepath, $out_filepath,array("sid"=>"6666","vid"=>"1.2"));

var_dump($out);

?>
