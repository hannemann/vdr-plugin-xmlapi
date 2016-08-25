/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   cPreset.cpp
 * Author: karl
 *
 * Created on 10. Februar 2016, 14:31
 */

#include "cPreset.h"
#include "helpers.h"

cPreset::cPreset(string cmd, string mimetype, string extension) {
    this->cmd = cmd;
    this->mimetype = mimetype;
    this->extension = extension;
}

cPreset::cPreset(const cPreset& src) {
    this->cmd = src.cmd;
    this->mimetype = src.mimetype;
    this->extension = src.extension;
}

cPreset::~cPreset() {
}

cPreset& cPreset::operator =(const cPreset& src) {
    if(this != &src) {
        this->cmd = src.cmd;
        this->mimetype = src.mimetype;
        this->extension = src.extension;
    }
    return *this;
}

string cPreset::FFmpegCmd(string input, int start) {
    string rstring = "{infile}";
    size_t start_pos = cmd.find(rstring);
    if(start_pos != std::string::npos)
    {
        cmd.replace(start_pos, rstring.length(), input);
    }
    rstring = "{start}";
    start_pos = cmd.find(rstring);
    if(start_pos != std::string::npos)
    {
        string s = "";
        if(start > 0) {
            s = " -ss " + intToString(start);
        }
        cmd.replace(start_pos, rstring.length(), s);
    }
    return cmd;
}

string cPreset::GetCmd() {
    return this->cmd;
}

string cPreset::MimeType() {
    return this->mimetype;
}

string cPreset::Extension() {
    return this->extension;
}
