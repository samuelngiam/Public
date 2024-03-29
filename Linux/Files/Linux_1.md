# KodeKloud - Linux Foundation Certified System Administrator (LFCS)

## Essential Commands

```
ls --help
Up-Arrow, Down-Arrow, Pg-Up, Pg-Down, q

man journalctl
man man

apropos director
sudo mandb

apropos -s 1,8 director
```

- Lab
```
ssh -V

apropos -s 1,8 hostname
man hostnamectl
hostnamectl set-hostname

mandb

ssh -v alex@localhost

host <Tab><Tab>

man man
8

ls -al /home/bob/data/
2

ssh bob@dev-host01
touch /home/bob/myfile
exit

sudo mandb
apropos ssh

apropos -s 5 nfs mount
echo nfsmount.conf > /home/bob/nfs
```

```
ls
ls -a
ls -l /var/log
ls -a -l
ls -al
ls -alh

/home/aaron/Documents/Invoice.pdf
/home/aaron/Documents

pwd
cd /var/log

cd /home/aaron
cd ..

cd /home/aaron
Documents/Invoice.pdf
Invoice.pdf
../Invoice.pdf
../../Invoice.pdf

cd /
cd -
cd
cd ~ 

touch Receipt.pdf
touch /home/jane/Receipt.pdf
touch ../jane/Receipt.pdf

mkdir Receipts
cp Receipt.pdf Receipts
cp Receipt.pdf Receipts/
cp Receipt.pdf Receipts/ReceiptCopy.pdf
cp -r Receipts/ BackupOfReceipts/
cp -r Receipts/ BackupOfReceipts/ (destination directory exists)

mv Receipt.pdf Receipts/
mv Receipt.pdf OldReceipt.pdf
mv Receipts/ OldReceipts/

rm Invoice.pdf
rm -r Invoices/

```
