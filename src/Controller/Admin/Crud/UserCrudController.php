<?php

namespace App\Controller\Admin\Crud;

use App\Entity\User;
use App\Service\Admin\CrudService;
use App\Service\Modules\ImageService;
use App\Entity\Category;
use App\Service\Modules\LangService;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\FormField;
use Doctrine\ORM\EntityManagerInterface;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Router\AdminUrlGenerator;
use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use App\Service\Modules\TranslateService;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Contracts\Translation\TranslatorInterface;

use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Length;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\ConstraintViolationListInterface;
use Symfony\Bundle\SecurityBundle\Security;

class UserCrudController extends AbstractCrudController
{

    private string $lang;

    public function __construct(
        private readonly AdminUrlGenerator $adminUrlGenerator,
        private ImageService $imageService,
        private readonly CrudService $crudService,
        private readonly LangService $langService,
        private readonly TranslateService $translateService,
        private readonly RequestStack $requestStack,
        private readonly TranslatorInterface $translator,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly Security $security
    ) {
        $this->lang = $this->langService->getDefault();
        if($this->requestStack->getCurrentRequest()){
            $locale = $this->requestStack->getCurrentRequest()->getSession()->get('_locale');
            if($locale){
                $this->lang = $this->requestStack->getCurrentRequest()->getSession()->get('_locale');
                $this->translateService->setLangs($this->lang);
                $this->langService->setLang($this->lang);
            }
        }
    }
    
    public static function getEntityFqcn(): string
    {
        return User::class;
    }

    public function persistEntity(EntityManagerInterface $entityManager, $entityInstance): void
    {
        if (!$entityInstance instanceof User) return;

        $this->checkAndSetPassword($entityInstance);

        $this->crudService->setEntity($entityManager, $entityInstance);
    }

    public function updateEntity(EntityManagerInterface $entityManager, $entityInstance): void
    {
        if (!$entityInstance instanceof User) return;

        $this->checkAndSetPassword($entityInstance);

        $this->crudService->setEntity($entityManager, $entityInstance);
    }

    public function configureFields(string $pageName): iterable
    {
        Category::setCurrentLang($this->lang);
        $this->getContext()->getRequest()->setLocale($this->lang);
        $this->translator->getCatalogue($this->lang);
        $this->translator->setLocale($this->lang);

        $choices = ['User' => 'ROLE_USER']; // Everyone can assign at least user role

        if ($this->security->isGranted('ROLE_SUPER_ADMIN')) {
            // SUPER_ADMIN can assign these roles
            $choices['Admin'] = 'ROLE_ADMIN';
            $choices['Super Admin'] = 'ROLE_SUPER_ADMIN';
        } elseif ($this->security->isGranted('ROLE_ADMIN')) {
            // ADMIN can assign ROLE_ADMIN but not ROLE_SUPER_ADMIN
            $choices['Admin'] = 'ROLE_ADMIN';
        }
        

        yield FormField::addTab($this->translateService->translateSzavak("options"));
            yield TextField::new('name', $this->translateService->translateSzavak("name"))
                ->hideOnIndex();
            yield TextField::new('name', $this->translateService->translateSzavak("name"))
                ->formatValue(function ($value, $entity) {
                    $url = $this->adminUrlGenerator
                        ->setController(self::class)
                        ->setAction('edit')
                        ->setEntityId($entity->getId())
                        ->generateUrl();

                    return sprintf('<a href="%s">%s</a>', $url, htmlspecialchars($value));
                })
                ->onlyOnIndex()
                ->renderAsHtml();
            yield TextField::new('email', $this->translateService->translateSzavak("email"));
            yield BooleanField::new('active',$this->translateService->translateSzavak("active"))
                ->renderAsSwitch(true)
                ->setFormTypeOptions(['data' => true]);
           yield TextField::new('password', $this->translateService->translateSzavak('password'))
                ->hideOnIndex()
                ->setFormType(RepeatedType::class)
                ->setFormTypeOptions([
                    'type' => PasswordType::class,
                    'invalid_message' => $this->translateService->translateSzavak('passwords_do_not_match'),
                    'first_options'  => ['label' => $this->translateService->translateSzavak('password')],
                    'second_options' => ['label' => $this->translateService->translateSzavak('password_again')],
                    'required' => $pageName === Crud::PAGE_NEW,
                    'constraints' => $pageName === Crud::PAGE_NEW ? [$this->getPasswordConstraints()] : [],
                    'mapped' => false, // Not mapped directly, handle manually
                ]);
            
            if ($this->security->isGranted('ROLE_ADMIN') || $this->security->isGranted('ROLE_SUPER_ADMIN')) {
                yield ChoiceField::new('roles', $this->translateService->translateSzavak('roles'))
                    ->setChoices($choices)
                    ->allowMultipleChoices()
                    ->hideOnIndex()
                    ->renderExpanded();
            }

        
    }

    public function userureCrud(Crud $crud): Crud
    {
        return $crud
            ->addFormTheme('@EasyAdmin/crud/form_theme.html.twig');
    }

    private function getPasswordConstraints(): Assert\Collection
    {
        return new Assert\Collection([
            new Assert\NotBlank([
                'message' => 'Password cannot be blank',
            ]),
            new Assert\Length([
                'min' => 8,
                'minMessage' => 'Password must be at least {{ limit }} characters long',
            ]),
            new Assert\Regex([
                'pattern' => '/[a-z]/',
                'message' => 'Password must contain at least one lowercase letter',
            ]),
            new Assert\Regex([
                'pattern' => '/[A-Z]/',
                'message' => 'Password must contain at least one uppercase letter',
            ]),
            new Assert\Regex([
                'pattern' => '/\d/',
                'message' => 'Password must contain at least one number',
            ]),
            new Assert\Regex([
                'pattern' => '/[\W_]/',
                'message' => 'Password must contain at least one special character',
            ]),
        ]);
    }

    private function validatePassword(string $password): ConstraintViolationListInterface
    {
        $validator = Validation::createValidator();
        $constraints = new Assert\Sequentially([
            new Assert\NotBlank(['message' => 'Password cannot be blank']),
            new Assert\Length(['min' => 8, 'minMessage' => 'Password must be at least {{ limit }} characters long']),
            new Assert\Regex(['pattern' => '/[a-z]/', 'message' => 'Password must contain at least one lowercase letter']),
            new Assert\Regex(['pattern' => '/[A-Z]/', 'message' => 'Password must contain at least one uppercase letter']),
            new Assert\Regex(['pattern' => '/\d/', 'message' => 'Password must contain at least one number']),
            new Assert\Regex(['pattern' => '/[\W_]/', 'message' => 'Password must contain at least one special character']),
        ]);

        return $validator->validate($password, $constraints);
    }

    private function checkAndSetPassword(User $entityInstance): void
    {
        $form = $this->getContext()->getRequest()->get('User'); // Adjust if form name differs
        if (!$form) {
            return; // No form submitted
        }

        $plainPassword = $form['password']['first'] ?? null;
        $repeatPassword = $form['password']['second'] ?? null;

        if ($plainPassword === null || $repeatPassword === null) {
            return;
        }

        if ($plainPassword !== $repeatPassword) {
            throw new \InvalidArgumentException($this->translateService->translateSzavak('passwords_do_not_match'));
        }

        $violations = $this->validatePassword($plainPassword);
        if (count($violations) > 0) {
            $messages = [];
            foreach ($violations as $violation) {
                $messages[] = $violation->getMessage();
            }
            throw new \InvalidArgumentException(implode("\n", $messages));
        }

        // Hash and set password
        $hashed = $this->passwordHasher->hashPassword($entityInstance, $plainPassword);
        $entityInstance->setPassword($hashed);
    }
}
