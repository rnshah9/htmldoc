//
// GUI license dialog routines for HTMLDOC, an HTML document processing
// program.
//
// Copyright 2011-2020 by Michael R Sweet.
// Copyright 1997-2010 by Easy Software Products.  All rights reserved.
//
// This program is free software.  Distribution and use rights are outlined in
// the file "COPYING".
//

#include "htmldoc.h"

#ifdef HAVE_LIBFLTK

//
// Include necessary headers.
//

#  include <FL/Fl_Box.H>
#  include <FL/Fl_Button.H>
#  include <FL/Fl_Group.H>
#  include <FL/Fl_Help_View.H>
#  include <FL/Fl_Output.H>


//
// Local functions...
//

static void	closeLicenseCB(Fl_Widget *w);


//
// 'GUI::showLicenseCB()' - Show the current license.
//

void
GUI::showLicenseCB(void)
{
  Fl_Window	*dialog;		// Dialog window
  Fl_Group	*group;			// Raised area
  Fl_Help_View	*help;			// License agreement viewer
  Fl_Button	*button;		// Button
  Fl_Box	*box;			// Text box


  // Create the window complete with the license agreement and
  // button to add a new license...
  dialog = new Fl_Window(640, 480, "HTMLDOC " SVERSION " License");
  dialog->set_modal();
  dialog->hotspot(dialog);

  group = new Fl_Group(10, 10, 620, 425, "HTMLDOC " SVERSION " License");
  group->align((Fl_Align)(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE));
  group->box(FL_THIN_UP_BOX);
  group->labelcolor(FL_BLUE);
  group->labelfont(FL_HELVETICA_BOLD);
  group->labelsize(18);

  box = new Fl_Box(20, 45, 600, 110,
    "Copyright © 2011-2022 by Michael R Sweet.\n\n"
    "HTMLDOC is provided under the terms of the GNU General Public License and "
    "comes with absolutely no warranty.  Please report problems on the Github "
    "issues page at:\n\n"
    "    https://github.com/michaelrsweet/htmldoc/issues\n"
  );

  box->align((Fl_Align)(FL_ALIGN_TOP_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP));

  help = new Fl_Help_View(20, 190, 600, 235, "Software License Agreement:");
  help->align(FL_ALIGN_TOP_LEFT);
  help->value(
    "<h3>GNU GENERAL PUBLIC LICENSE</h3>\n"
    "<p>Version 2, June 1991 "
    "<pre>\n"
    "Copyright 1989, 1991 Free Software Foundation, Inc.\n"
    "59 Temple Place, Suite 330, Boston, MA 02111-1307 USA\n"
    "Everyone is permitted to copy and distribute verbatim\n"
    "copies of this license document, but changing it is not\n"
    "allowed.\n"
    "\n"
    "</pre>\n"
    "<h4>Preamble</h4>\n"
    "<p>The licenses for most software are designed to take away your "
    "freedom to share and change it.  By contrast, the GNU General Public "
    "License is intended to guarantee your freedom to share and change free "
    "software--to make sure the software is free for all its users.  This "
    "General Public License applies to most of the Free Software "
    "Foundation's software and to any other program whose authors commit to "
    "using it.  (Some other Free Software Foundation software is covered by "
    "the GNU Library General Public License instead.)  You can apply it to "
    "your programs, too. "
    "<p>When we speak of free software, we are referring to freedom, not "
    "price.  Our General Public Licenses are designed to make sure that you "
    "have the freedom to distribute copies of free software (and charge for "
    "this service if you wish), that you receive source code or can get it "
    "if you want it, that you can change the software or use pieces of it "
    "in new free programs; and that you know you can do these things. "
    "<p>To protect your rights, we need to make restrictions that forbid "
    "anyone to deny you these rights or to ask you to surrender the rights. "
    "These restrictions translate to certain responsibilities for you if you "
    "distribute copies of the software, or if you modify it. "
    "<p>For example, if you distribute copies of such a program, whether "
    "gratis or for a fee, you must give the recipients all the rights that "
    "you have.  You must make sure that they, too, receive or can get the "
    "source code.  And you must show them these terms so they know their "
    "rights. "
    "<p>We protect your rights with two steps: (1) copyright the software, and "
    "(2) offer you this license which gives you legal permission to copy, "
    "distribute and/or modify the software. "
    "<p>Also, for each author's protection and ours, we want to make certain "
    "that everyone understands that there is no warranty for this free "
    "software.  If the software is modified by someone else and passed on, we "
    "want its recipients to know that what they have is not the original, so "
    "that any problems introduced by others will not reflect on the original "
    "authors' reputations. "
    "<p>Finally, any free program is threatened constantly by software "
    "patents.  We wish to avoid the danger that redistributors of a free "
    "program will individually obtain patent licenses, in effect making the "
    "program proprietary.  To prevent this, we have made it clear that any "
    "patent must be licensed for everyone's free use or not licensed at all. "
    "<p>The precise terms and conditions for copying, distribution and "
    "modification follow. "
    "<h4>GNU GENERAL PUBLIC LICENSE<BR>\n"
    "TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION</h4>\n"
    "<p>0. This License applies to any program or other work which contains "
    "a notice placed by the copyright holder saying it may be distributed "
    "under the terms of this General Public License.  The \"Program\", below, "
    "refers to any such program or work, and a \"work based on the Program\" "
    "means either the Program or any derivative work under copyright law: "
    "that is to say, a work containing the Program or a portion of it, "
    "either verbatim or with modifications and/or translated into another "
    "language.  (Hereinafter, translation is included without limitation in "
    "the term \"modification\".)  Each licensee is addressed as \"you\". "
    "<p>Activities other than copying, distribution and modification are not "
    "covered by this License; they are outside its scope.  The act of "
    "running the Program is not restricted, and the output from the Program "
    "is covered only if its contents constitute a work based on the "
    "Program (independent of having been made by running the Program). "
    "Whether that is true depends on what the Program does. "
    "<p>1. You may copy and distribute verbatim copies of the Program's "
    "source code as you receive it, in any medium, provided that you "
    "conspicuously and appropriately publish on each copy an appropriate "
    "copyright notice and disclaimer of warranty; keep intact all the "
    "notices that refer to this License and to the absence of any warranty; "
    "and give any other recipients of the Program a copy of this License "
    "along with the Program. "
    "<p>You may charge a fee for the physical act of transferring a copy, and "
    "you may at your option offer warranty protection in exchange for a fee. "
    "<p>2. You may modify your copy or copies of the Program or any portion "
    "of it, thus forming a work based on the Program, and copy and "
    "distribute such modifications or work under the terms of Section 1 "
    "above, provided that you also meet all of these conditions: "
    "<p>a. You must cause the modified files to carry prominent notices "
    "stating that you changed the files and the date of any change. "
    "<p>b. You must cause any work that you distribute or publish, that in "
    "whole or in part contains or is derived from the Program or any "
    "part thereof, to be licensed as a whole at no charge to all third "
    "parties under the terms of this License. "
    "<p>c. if the modified program normally reads commands interactively "
    "when run, you must cause it, when started running for such "
    "interactive use in the most ordinary way, to print or display an "
    "announcement including an appropriate copyright notice and a "
    "notice that there is no warranty (or else, saying that you provide "
    "a warranty) and that users may redistribute the program under "
    "these conditions, and telling the user how to view a copy of this "
    "License.  (Exception: if the Program itself is interactive but "
    "does not normally print such an announcement, your work based on "
    "the Program is not required to print an announcement.) "
    "<p>These requirements apply to the modified work as a whole.  If "
    "identifiable sections of that work are not derived from the Program, "
    "and can be reasonably considered independent and separate works in "
    "themselves, then this License, and its terms, do not apply to those "
    "sections when you distribute them as separate works.  But when you "
    "distribute the same sections as part of a whole which is a work based "
    "on the Program, the distribution of the whole must be on the terms of "
    "this License, whose permissions for other licensees extend to the "
    "entire whole, and thus to each and every part regardless of who wrote it. "
    "<p>Thus, it is not the intent of this section to claim rights or contest "
    "your rights to work written entirely by you; rather, the intent is to "
    "exercise the right to control the distribution of derivative or "
    "collective works based on the Program. "
    "<p>In addition, mere aggregation of another work not based on the Program "
    "with the Program (or with a work based on the Program) on a volume of "
    "a storage or distribution medium does not bring the other work under "
    "the scope of this License. "
    "<p>3. You may copy and distribute the Program (or a work based on it, "
    "under Section 2) in object code or executable form under the terms of "
    "Sections 1 and 2 above provided that you also do one of the following: "
    "<p>a. Accompany it with the complete corresponding machine-readable "
    "source code, which must be distributed under the terms of Sections "
    "1 and 2 above on a medium customarily used for software interchange; or, "
    "<p>b. Accompany it with a written offer, valid for at least three "
    "years, to give any third party, for a charge no more than your "
    "cost of physically performing source distribution, a complete "
    "machine-readable copy of the corresponding source code, to be "
    "distributed under the terms of Sections 1 and 2 above on a medium "
    "customarily used for software interchange; or, "
    "<p>c. Accompany it with the information you received as to the offer "
    "to distribute corresponding source code.  (This alternative is "
    "allowed only for noncommercial distribution and only if you "
    "received the program in object code or executable form with such "
    "an offer, in accord with Subsection b above.) "
    "<p>The source code for a work means the preferred form of the work for "
    "making modifications to it.  For an executable work, complete source "
    "code means all the source code for all modules it contains, plus any "
    "associated interface definition files, plus the scripts used to "
    "control compilation and installation of the executable.  However, as a "
    "special exception, the source code distributed need not include "
    "anything that is normally distributed (in either source or binary "
    "form) with the major components (compiler, kernel, and so on) of the "
    "operating system on which the executable runs, unless that component "
    "itself accompanies the executable. "
    "<p>If distribution of executable or object code is made by offering "
    "access to copy from a designated place, then offering equivalent "
    "access to copy the source code from the same place counts as "
    "distribution of the source code, even though third parties are not "
    "compelled to copy the source along with the object code. "
    "<p>4. You may not copy, modify, sublicense, or distribute the Program "
    "except as expressly provided under this License.  Any attempt "
    "otherwise to copy, modify, sublicense or distribute the Program is "
    "void, and will automatically terminate your rights under this License. "
    "However, parties who have received copies, or rights, from you under "
    "this License will not have their licenses terminated so long as such "
    "parties remain in full compliance. "
    "<p>5. You are not required to accept this License, since you have not "
    "signed it.  However, nothing else grants you permission to modify or "
    "distribute the Program or its derivative works.  These actions are "
    "prohibited by law if you do not accept this License.  Therefore, by "
    "modifying or distributing the Program (or any work based on the "
    "Program), you indicate your acceptance of this License to do so, and "
    "all its terms and conditions for copying, distributing or modifying "
    "the Program or works based on it. "
    "<p>6. Each time you redistribute the Program (or any work based on the "
    "Program), the recipient automatically receives a license from the "
    "original licensor to copy, distribute or modify the Program subject to "
    "these terms and conditions.  You may not impose any further "
    "restrictions on the recipients' exercise of the rights granted herein. "
    "You are not responsible for enforcing compliance by third parties to "
    "this License. "
    "<p>7. If, as a consequence of a court judgment or allegation of patent "
    "infringement or for any other reason (not limited to patent issues), "
    "conditions are imposed on you (whether by court order, agreement or "
    "otherwise) that contradict the conditions of this License, they do not "
    "excuse you from the conditions of this License.  If you cannot "
    "distribute so as to satisfy simultaneously your obligations under this "
    "License and any other pertinent obligations, then as a consequence you "
    "may not distribute the Program at all.  For example, if a patent "
    "license would not permit royalty-free redistribution of the Program by "
    "all those who receive copies directly or indirectly through you, then "
    "the only way you could satisfy both it and this License would be to "
    "refrain entirely from distribution of the Program. "
    "<p>If any portion of this section is held invalid or unenforceable under "
    "any particular circumstance, the balance of the section is intended to "
    "apply and the section as a whole is intended to apply in other "
    "circumstances. "
    "<p>It is not the purpose of this section to induce you to infringe any "
    "patents or other property right claims or to contest validity of any "
    "such claims; this section has the sole purpose of protecting the "
    "integrity of the free software distribution system, which is "
    "implemented by public license practices.  Many people have made "
    "generous contributions to the wide range of software distributed "
    "through that system in reliance on consistent application of that "
    "system; it is up to the author/donor to decide if he or she is willing "
    "to distribute software through any other system and a licensee cannot "
    "impose that choice. "
    "<p>This section is intended to make thoroughly clear what is believed to "
    "be a consequence of the rest of this License. "
    "<p>8. If the distribution and/or use of the Program is restricted in "
    "certain countries either by patents or by copyrighted interfaces, the "
    "original copyright holder who places the Program under this License "
    "may add an explicit geographical distribution limitation excluding "
    "those countries, so that distribution is permitted only in or among "
    "countries not thus excluded.  In such case, this License incorporates "
    "the limitation as if written in the body of this License. "
    "<p>9. The Free Software Foundation may publish revised and/or new versions "
    "of the General Public License from time to time.  Such new versions will "
    "be similar in spirit to the present version, but may differ in detail to "
    "address new problems or concerns. "
    "<p>Each version is given a distinguishing version number.  If the Program "
    "specifies a version number of this License which applies to it and \"any "
    "later version\", you have the option of following the terms and conditions "
    "either of that version or of any later version published by the Free "
    "Software Foundation.  If the Program does not specify a version number of "
    "this License, you may choose any version ever published by the Free Software "
    "Foundation. "
    "<p>10. If you wish to incorporate parts of the Program into other free "
    "programs whose distribution conditions are different, write to the author "
    "to ask for permission.  For software which is copyrighted by the Free "
    "Software Foundation, write to the Free Software Foundation; we sometimes "
    "make exceptions for this.  Our decision will be guided by the two goals "
    "of preserving the free status of all derivatives of our free software and "
    "of promoting the sharing and reuse of software generally. "
    "<h4>NO WARRANTY</h4>\n"
    "<p>11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY "
    "FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN "
    "OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES "
    "PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED "
    "OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF "
    "MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS "
    "TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE "
    "PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, "
    "REPAIR OR CORRECTION. "
    "<p>IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING "
    "WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR "
    "REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, "
    "INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING "
    "OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED "
    "TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY "
    "YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER "
    "PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE "
    "POSSIBILITY OF SUCH DAMAGES. "
    "<h4>END OF TERMS AND CONDITIONS</h4>\n"
    "<h4>How to Apply These Terms to Your New Programs</h3>\n"
    "\n"
    "<p>If you develop a new program, and you want it to be of the greatest\n"
    "possible use to the public, the best way to achieve this is to make it\n"
    "free software which everyone can redistribute and change under these terms.\n"
    "\n"
    "<p>To do so, attach the following notices to the program.  It is safest\n"
    "to attach them to the start of each source file to most effectively\n"
    "convey the exclusion of warranty; and each file should have at least\n"
    "the \"copyright\" line and a pointer to where the full notice is found.\n"
    "\n"
    "<pre>\n"
    "<var>one line to give the program's name and an idea of what it does.</var>\n"
    "Copyright (C) <var>yyyy</var>  <var>name of author</var>\n"
    "\n"
    "This program is free software; you can redistribute it and/or\n"
    "modify it under the terms of the GNU General Public License\n"
    "as published by the Free Software Foundation; either version 2\n"
    "of the License, or (at your option) any later version.\n"
    "\n"
    "This program is distributed in the hope that it will be useful,\n"
    "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
    "GNU General Public License for more details.\n"
    "\n"
    "You should have received a copy of the GNU General Public License\n"
    "along with this program; if not, write to the Free Software\n"
    "Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.\n"
    "</pre>\n"
    "\n"
    "<p>Also add information on how to contact you by electronic and paper mail.\n"
    "\n"
    "<p>If the program is interactive, make it output a short notice like this\n"
    "when it starts in an interactive mode:\n"
    "\n"
    "<pre>\n"
    "Gnomovision version 69, Copyright (C) <var>year</var> <var>name of author</var>\n"
    "Gnomovision comes with ABSOLUTELY NO WARRANTY; for details\n"
    "type `show w'.  This is free software, and you are welcome\n"
    "to redistribute it under certain conditions; type `show c' \n"
    "for details.\n"
    "</pre>\n"
    "\n"
    "<p>The hypothetical commands <samp>`show w'</samp> and <samp>`show c'</samp> should show\n"
    "the appropriate parts of the General Public License.  Of course, the\n"
    "commands you use may be called something other than <samp>`show w'</samp> and\n"
    "<samp>`show c'</samp>; they could even be mouse-clicks or menu items--whatever\n"
    "suits your program.\n"
    "\n"
    "<p>You should also get your employer (if you work as a programmer) or your\n"
    "school, if any, to sign a \"copyright disclaimer\" for the program, if\n"
    "necessary.  Here is a sample; alter the names:\n"
    "\n"
    "<pre>\n"
    "Yoyodyne, Inc., hereby disclaims all copyright\n"
    "interest in the program `Gnomovision'\n"
    "(which makes passes at compilers) written \n"
    "by James Hacker.\n"
    "\n"
    "<var>signature of Ty Coon</var>, 1 April 1989\n"
    "Ty Coon, President of Vice\n"
    "</pre>\n"
  );

  group->end();

  button = new Fl_Button(565, 445, 65, 25, "Close");
  button->callback((Fl_Callback *)closeLicenseCB);

  // Show the window and wait...
  dialog->end();
  dialog->show();

  while (dialog->shown())
    Fl::wait();

  delete dialog;
}


//
// 'closeLicenseCB()' - Close the license window.
//

static void
closeLicenseCB(Fl_Widget *w)		// I - Close button
{
  if (w && w->window())
    w->window()->hide();
}


#endif // HAVE_LIBFLTK
