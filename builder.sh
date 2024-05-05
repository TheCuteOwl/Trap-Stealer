echo -en "\033]0;trap stealer\007"


echo
echo ________                               ____                           ___                 
echo MMMMMMMMMM                              6MMMMb\                         `MM                 
echo /   MM   \                             6M'    `  /                       MM                 
echo     MM ___  __    ___  __ ____         MM       /M      ____      ___    MM   ____  ___  __ 
echo     MM `MM 6MM  6MMMMb `M6MMMMb        YM.     /MMMMM  6MMMMb   6MMMMb   MM  6MMMMb `MM 6MM 
echo     MM  MM69 " 8M'  `Mb MM'  `Mb        YMMMMb  MM    6M'  `Mb 8M'  `Mb  MM 6M'  `Mb MM69 " 
echo     MM  MM'        ,oMM MM    MM            `Mb MM    MM    MM     ,oMM  MM MM    MM MM'    
echo     MM  MM     ,6MM9'MM MM    MM             MM MM    MMMMMMMM ,6MM9'MM  MM MMMMMMMM MM     
echo     MM  MM     MM'   MM MM    MM             MM MM    MM       MM'   MM  MM MM       MM     
echo     MM  MM     MM.  ,MM MM.  ,M9       L    ,M9 YM.  ,YM    d9 MM.  ,MM  MM YM    d9 MM     
echo    _MM__MM_    `YMMM9'YbMMYMMM9        MYMMMM9   YMMM9 YMMMM9  `YMMM9'Yb_MM_ YMMMM9 _MM_    
echo                        MM                                                                  
echo                        MM                                                                  
echo                       _MM_                                       
echo
echo
echo Coded By https://github.com/TheCuteOwl/
echo 
echo Press any key to continue with the builder.
read -n 1 -s -r -p ""
echo ""
python builder.py

if [ $? -eq 1 ]; then
    echo error during build...
    time (sleep 1)
    Installing packages...
    time (sleep 1)
    pip3 install -r requirements.txt
    echo Installation complete!
fi

