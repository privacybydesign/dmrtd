// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// MRTD data model for passport reading

import 'dart:typed_data';
import 'package:dmrtd/dmrtd.dart';

/// Data model for MRTD passport information
class MrtdData {
  EfCardAccess? cardAccess;
  EfCardSecurity? cardSecurity;
  EfCOM? com;
  EfSOD? sod;
  EfDG1? dg1;
  EfDG2? dg2;
  EfDG3? dg3;
  EfDG4? dg4;
  EfDG5? dg5;
  EfDG6? dg6;
  EfDG7? dg7;
  EfDG8? dg8;
  EfDG9? dg9;
  EfDG10? dg10;
  EfDG11? dg11;
  EfDG12? dg12;
  EfDG13? dg13;
  EfDG14? dg14;
  EfDG15? dg15;
  EfDG16? dg16;
  Uint8List? aaSig;
  bool? isPACE;
  bool? isDBA;
  
  /// Constructor
  MrtdData();
  
  /// Check if any data is available
  bool get hasData => 
    cardAccess != null || 
    cardSecurity != null ||
    com != null ||
    sod != null ||
    dg1 != null ||
    dg2 != null ||
    dg3 != null ||
    dg4 != null ||
    dg5 != null ||
    dg6 != null ||
    dg7 != null ||
    dg8 != null ||
    dg9 != null ||
    dg10 != null ||
    dg11 != null ||
    dg12 != null ||
    dg13 != null ||
    dg14 != null ||
    dg15 != null ||
    dg16 != null ||
    aaSig != null;
}