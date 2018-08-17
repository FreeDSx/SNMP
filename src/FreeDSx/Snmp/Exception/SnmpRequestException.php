<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Exception;

use FreeDSx\Snmp\Message\ErrorStatus;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Snmp\Response\Response;

/**
 * Represents a generic SNMP request exception.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SnmpRequestException extends \Exception
{
    protected const ERROR_MAP = [
        ErrorStatus::TOO_BIG => 'The determined message size is greater than either a local constraint or the maximum message size of the originator (TooBig).',
        ErrorStatus::NO_SUCH_NAME => 'The requested OID (%s) cannot be returned (NoSuchName).',
        ErrorStatus::BAD_VALUE => 'The requested OID (%s) cannot be changed due to a value or syntax error (BadValue).',
        ErrorStatus::READ_ONLY => 'The requested OID (%s) cannot be changed as it is read-only (ReadOnly).',
        ErrorStatus::GEN_ERROR => 'A generic error was encountered during the request (GenError).',
        ErrorStatus::NO_ACCESS => 'The requested OID (%s) is not accessible (NoAccess).',
        ErrorStatus::WRONG_TYPE => 'The requested OID (%s) specifies a value type that is inconsistent with the type required for the variable (WrongType).',
        ErrorStatus::WRONG_LENGTH => 'The requested OID (%s) specifies a value length that is inconsistent with the type required for the variable (WrongLength).',
        ErrorStatus::WRONG_ENCODING => 'The requested OID (%s) contains an ASN.1 encoding that is invalid with the type required for the variable (WrongEncoding).',
        ErrorStatus::WRONG_VALUE => 'The requested OID (%s) value cannot be assigned to the variable (WrongValue).',
        ErrorStatus::NO_CREATION => 'The requested OID (%s) variable does not exist and the agent cannot create it (NoCreation).',
        ErrorStatus::INCONSISTENT_VALUE => 'The requested OID (%s) value is inconsistent with the value of other managed objects (InconsistentValue).',
        ErrorStatus::RESOURCE_UNAVAILABLE => 'The requested OID (%s) value cannot be assigned as the required allocation of resources is unavailable (ResourceUnavailable).',
        ErrorStatus::COMMIT_FAILED => 'The requested OID (%s) value could not not committed (CommitFailed).',
        ErrorStatus::UNDO_FAILED => 'Some OIDs were updated because it was not possible to undo the operation (UndoFailed).',
        ErrorStatus::AUTHORIZATION_ERROR => 'An authorization error occurred (AuthorizationError).',
        ErrorStatus::NOT_WRITABLE => 'The requested OID (%s) exists but the agent cannot modify it (NotWritable).',
        ErrorStatus::INCONSISTENT_NAME => 'The requested OID (%s) does not exist and cannot be created (InconsistentName).',
    ];

    /**
     * @var null|MessageResponseInterface
     */
    protected $snmpMessage;

    /**
     * @param MessageResponseInterface $response
     * @param null|string $message
     * @param \Throwable|null $previous
     */
    public function __construct(?MessageResponseInterface $response, ?string $message = null, \Throwable $previous = null)
    {
        $this->snmpMessage = $response;
        $errorCode = $response ? $response->getResponse()->getErrorStatus() : 0;

        if ($message === null && $response) {
            $message = $this->generateMessage($response);
        } else {
            $message = (string) $message;
        }

        parent::__construct($message, $errorCode, $previous);
    }

    /**
     * @return Pdu|Response|ReportResponse
     */
    public function getResponse() : ?Pdu
    {
        return $this->snmpMessage ? $this->snmpMessage->getResponse() : null;
    }

    /**
     * @return MessageResponseInterface
     */
    public function getSnmpMessage() : ?MessageResponseInterface
    {
        return $this->snmpMessage;
    }

    /**
     * @param MessageResponseInterface $response
     * @return string
     */
    protected function generateMessage(MessageResponseInterface $response) : string
    {
        if (isset(self::ERROR_MAP[$response->getResponse()->getErrorStatus()])) {
            $oid = '';
            $errorIndex = $response->getResponse()->getErrorIndex();
            if ($errorIndex !== 0) {
                $oid = $response->getResponse()->getOids()->index($errorIndex)->getOid();
            }
            $message = sprintf(self::ERROR_MAP[$response->getResponse()->getErrorStatus()], $oid);
        } else {
            $message = 'An error was encountered during the SNMP request.';
        }

        return $message;
    }
}
