package de.fhg.aisec.ids.clearinghouse.idscp2

import de.fhg.aisec.ids.clearinghouse.QueryResult
import de.fhg.aisec.ids.clearinghouse.Utility
import de.fhg.aisec.ids.clearinghouse.Utility.Companion.STATUS_403
import de.fhg.aisec.ids.clearinghouse.Utility.Companion.STATUS_404
import de.fhg.aisec.ids.clearinghouse.Utility.Companion.formatId
import de.fhg.aisec.ids.clearinghouse.Utility.Companion.parseQueryResult
import de.fhg.aisec.ids.clearinghouse.idscp2.CreatePidTests.Companion.succCreatePid
import de.fhg.aisec.ids.clearinghouse.idscp2.QueryIdTests.Companion.failQueryId
import de.fhg.aisec.ids.clearinghouse.multipart.QueryPidTests
import de.fraunhofer.iais.eis.ResultMessage
import org.junit.Assert
import org.junit.jupiter.api.Test

class QueryPidTests {
    @Test
    fun queryPid1(){
        val pid = formatId("idscp-qpid1")

        // create Pid
        succCreatePid(pid, null)

        // Test: query existing Pid with no documents
        val result = QueryPidTests.succQueryPid(pid)
        Assert.assertEquals("Should receive empty array!", 0, result.documents.size)
    }

    @Test
    fun queryPid2(){
        val pid = formatId("idscp-qpid2")

        // create Pid with three messages
        val messages = listOf("This is the first message", "This is the second message", "This is the third message")
        messages.forEach{
            LogMessageTests.succLogMessage(pid, it)
        }

        // Test: query existing Pid with three documents
        val result = QueryPidTests.succQueryPid(pid)
        Assert.assertEquals("Should receive empty array!", 3, result.documents.size)
    }

    @Test
    fun queryPid3(){
        val pid = formatId("idscp-qpid3")
        val owners = listOf(Utility.CONNECTOR_1)

        // create Pid with other user, but user 1 is also authorized
        succCreatePid(pid, owners, client = 2)

        // add three messages
        val messages = listOf("This is the first message", "This is the second message", "This is the third message")
        messages.forEach{
            LogMessageTests.succLogMessage(pid, it, c = 2)
        }

        // Test: query existing Pid with user (who did not create pid, but is authorized)
        val result = QueryPidTests.succQueryPid(pid)
        Assert.assertEquals("Should receive empty array!", 3, result.documents.size)
    }

    @Test
    fun queryPid4(){
        val pid = formatId("idscp-qpid4")

        // Test: query non-existing Pid
        failQueryPid(pid, STATUS_404)
    }

    @Test
    fun queryPid5(){
        val pid = formatId("idscp-qpid5")

        // create Pid with other user
        succCreatePid(pid, null, client = 2)

        // Test: query existing Pid with user (for which he is not authorized)
        failQueryPid(pid, STATUS_403)
    }

    companion object{

        fun failQueryPid(pid: String, em: String) {
            return failQueryId(pid, null, em)
        }

        fun succQueryPid(pid: String): QueryResult {
            val (resultMessage, resultPayload, resultHeaders) = Idscp2EndpointTest.queryMessage(pid, null, "")
            // check IDS message type
            Assert.assertTrue(resultMessage is ResultMessage)
            // check the pid from receipt in the payload. Does pid match with the given pid?
            return parseQueryResult(String(resultPayload!!))
        }
    }

}