use 5.026002;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Crypt::PBKDF2::PatchXS',
    VERSION_FROM      => 'lib/Crypt/PBKDF2/PatchXS.pm',
    PREREQ_PM         => { 'Crypt::PBKDF2' => 0.1, },
    ABSTRACT_FROM     => 'lib/Crypt/PBKDF2/PatchXS.pm',
    AUTHOR            => 'Staff',
    #LICENSE           => 'perl',
    #Value must be from legacy list of licenses here
    #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    # OBJECT            => '$(O_FILES)', # link all the C files too
);
